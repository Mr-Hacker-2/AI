import asyncio
import json
import logging
import multiprocessing
import os
import sys
import threading
import time
from pathlib import Path

import cv2
import glob
import psutil
from fastapi import APIRouter, Response, WebSocket, WebSocketDisconnect
from fastapi.responses import StreamingResponse

logger = logging.getLogger(__name__)

# Project root for hailo_od and default HEF
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# --- Constants from camera_stream.py ---
STREAM_WIDTH = 640
STREAM_HEIGHT = 384
STREAM_FPS = 30
DETECTION_FRAME_INTERVAL = 3
PERSON_DETECTED_COOLDOWN = 30  # seconds between person detection alerts

# --- Person Detection Alert Callback ---
_person_detection_callback = None
_last_person_alert_time = 0

def set_person_detection_callback(callback):
    """Set a callback to be called when a person is detected."""
    global _person_detection_callback
    _person_detection_callback = callback

def trigger_person_alert():
    """Trigger person detection alert with cooldown."""
    global _last_person_alert_time
    import time
    current_time = time.time()
    if current_time - _last_person_alert_time > PERSON_DETECTED_COOLDOWN:
        _last_person_alert_time = current_time
        if _person_detection_callback:
            try:
                _person_detection_callback()
            except Exception as e:
                logger.error(f"Person alert callback error: {e}")

# --- Camera Process Logic ---
CAMERA_RESTART_DELAY = 2.0   # seconds to wait before reinit after timeout
CAMERA_MAX_CAPTURE_RETRIES = 5   # retries per frame before considering it a timeout

def run_stream_process(
    stream_queue: multiprocessing.Queue,
    stop_event: multiprocessing.Event,
    detection_enabled: multiprocessing.Value = None,
    detection_queue: multiprocessing.Queue = None,
    width: int = STREAM_WIDTH,
    height: int = STREAM_HEIGHT,
):
    camera = None
    camera_type = None
    camera_index = int(os.environ.get("CAMERA_INDEX", "-1"))

    def init_picamera():
        from picamera2 import Picamera2
        picam2 = Picamera2()
        main = {"size": (1280, 720), "format": "RGB888"}
        lores = {"size": (width, height), "format": "RGB888"}
        controls = {"FrameRate": STREAM_FPS, "AfMode": 2, "AfRange": 2}
        config = picam2.create_preview_configuration(main=main, lores=lores, controls=controls)
        picam2.configure(config)
        picam2.start()
        time.sleep(0.5)
        return picam2

    def init_usb_camera():
        if camera_index >= 0:
            cap = cv2.VideoCapture(camera_index)
            if cap is not None and cap.isOpened():
                cap.set(cv2.CAP_PROP_FRAME_WIDTH, 1280)
                cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 720)
                cap.set(cv2.CAP_PROP_FPS, STREAM_FPS)
                ret, frame = cap.read()
                if ret and frame is not None:
                    logger.info("USB camera opened on device index %d", camera_index)
                    return cap
                cap.release()
        for device_idx in range(10):
            cap = cv2.VideoCapture(device_idx)
            if cap is not None and cap.isOpened():
                cap.set(cv2.CAP_PROP_FRAME_WIDTH, 1280)
                cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 720)
                cap.set(cv2.CAP_PROP_FPS, STREAM_FPS)
                ret, frame = cap.read()
                if ret and frame is not None:
                    logger.info("USB camera opened on device index %d", device_idx)
                    return cap
                cap.release()
        return None

    def stop_camera_safe(cam, cam_type):
        try:
            if cam_type == "picamera2":
                try:
                    cam.stop()
                except Exception:
                    pass
                try:
                    cam.close()
                except Exception:
                    pass
            elif cam_type == "usb":
                try:
                    cam.release()
                except Exception:
                    pass
        except Exception:
            pass

    try:
        camera = init_usb_camera()
        if camera is not None:
            camera_type = "usb"
            logger.info("Using USB camera")
        else:
            try:
                camera = init_picamera()
                camera_type = "picamera2"
                logger.info("Using Picamera2")
            except Exception as e:
                logger.warning("Picamera2 init failed: %s", e)
                logger.error("No camera found")
                return
    except Exception as e:
        logger.error("Camera init failed: %s", e)
        return

    frame_count = 0
    try:
        while not stop_event.is_set():
            frame_data = None
            for attempt in range(CAMERA_MAX_CAPTURE_RETRIES):
                try:
                    if camera_type == "picamera2":
                        frame_data = camera.capture_array("lores")
                    elif camera_type == "usb":
                        ret, frame_data = camera.read()
                        if not ret:
                            frame_data = None
                    break
                except Exception as e:
                    if attempt + 1 >= CAMERA_MAX_CAPTURE_RETRIES:
                        logger.error("Device timeout detected, attempting a restart: %s", e)
                        stop_camera_safe(camera, camera_type)
                        camera = None
                        time.sleep(CAMERA_RESTART_DELAY)
                        if stop_event.is_set():
                            return
                        try:
                            try:
                                camera = init_picamera()
                                camera_type = "picamera2"
                            except Exception:
                                camera = init_usb_camera()
                                camera_type = "usb"
                            if camera is None:
                                logger.error("Camera restart failed")
                                return
                        except Exception as e2:
                            logger.error("Camera restart failed: %s", e2)
                            return
                        break
                    time.sleep(0.1)

            if frame_data is None:
                continue

            if len(frame_data.shape) == 2:
                frame = cv2.cvtColor(frame_data, cv2.COLOR_GRAY2RGB)
            elif frame_data.shape[2] == 3:
                frame = cv2.cvtColor(frame_data, cv2.COLOR_BGR2RGB)
            else:
                frame = cv2.cvtColor(frame_data, cv2.COLOR_BGR2RGB)

            try:
                stream_queue.put_nowait(frame)
            except Exception:
                pass

            if detection_enabled is not None and detection_queue is not None:
                if detection_enabled.value and frame_count % DETECTION_FRAME_INTERVAL == 0:
                    try:
                        detection_queue.put_nowait(frame)
                    except Exception:
                        pass
            frame_count += 1
    finally:
        if camera is not None:
            stop_camera_safe(camera, camera_type)

# --- Router Logic ---
router = APIRouter()

# Global camera state
camera_process = None
stop_event = multiprocessing.Event()
stream_queue = multiprocessing.Queue(maxsize=1)
detection_enabled = multiprocessing.Value('b', False)
detection_queue = multiprocessing.Queue(maxsize=1)

# Detection worker: WebSocket broadcast (main thread / asyncio)
_detection_ws_set = set()
_detection_ws_lock = threading.Lock()
_detection_loop = None
_latest_detections = []
_latest_detections_lock = threading.Lock()
_detection_worker_thread = None
_detection_worker_stop = threading.Event()
DEFAULT_HEF = PROJECT_ROOT / "models" / "yolov11l.hef"
CONFIG_PATH = PROJECT_ROOT / "hailo_od" / "config.json"


def _run_detection_worker():
    """Runs in a background thread: read frames from detection_queue, run Hailo, push detections for broadcast."""
    import numpy as np
    infer = None
    labels = []
    config_data = {}
    width = height = 640

    try:
        from hailo_od.hailo_inference import HailoInfer
        from hailo_od.toolbox import get_labels, load_json_file, default_preprocess
        from hailo_od.object_detection_post_process import extract_detections
    except Exception as e:
        logger.warning("[detection] hailo_od import failed: %s", e)
        return

    hef_path = str(DEFAULT_HEF)
    if not os.path.isfile(hef_path):
        logger.warning("[detection] HEF not found: %s", hef_path)
        return

    result_holder = []
    done_ev = threading.Event()

    def on_done(completion_info, bindings_list=None):
        if completion_info.exception:
            result_holder.append(("err", None))
        else:
            b = bindings_list[0]
            if len(b._output_names) == 1:
                result_holder.append(("ok", b.output().get_buffer()))
            else:
                result_holder.append(("ok", {
                    n: np.expand_dims(b.output(n).get_buffer(), axis=0)
                    for n in b._output_names
                }))
        done_ev.set()

    while not _detection_worker_stop.is_set():
        if not detection_enabled.value:
            time.sleep(0.3)
            continue

        if infer is None:
            try:
                infer = HailoInfer(hef_path, batch_size=1)
                height, width, _ = infer.get_input_shape()
                labels = get_labels(None)
                config_data = (
                    json.load(open(CONFIG_PATH)) if CONFIG_PATH.exists() else
                    {"visualization_params": {"score_thres": 0.25, "max_boxes_to_draw": 50}}
                )
                logger.info("[detection] Hailo model loaded")
            except Exception as e:
                logger.warning("[detection] model load failed: %s", e)
                time.sleep(1)
                continue

        try:
            frame = detection_queue.get(timeout=1.0)
        except Exception:
            continue

        # Frame is 640x384 (lores). Preprocess to model input (e.g. 640x640)
        preprocessed = default_preprocess(frame, width, height)
        result_holder.clear()
        done_ev.clear()
        try:
            infer.run([preprocessed], on_done)
            done_ev.wait(timeout=5.0)
        except Exception as e:
            logger.warning("[detection] inference error: %s", e)
            continue

        if not result_holder or result_holder[0][0] != "ok":
            continue

        raw = result_holder[0][1]
        # raw may be single array or dict; extract_detections expects list of per-class arrays
        try:
            if isinstance(raw, dict):
                dets_list = list(raw.values())
            elif hasattr(raw, "shape") and len(raw.shape) >= 2:
                dets_list = _raw_to_per_class_list(raw)
            else:
                dets_list = raw if isinstance(raw, list) else [raw]
            det_dict = extract_detections(frame, dets_list, config_data)
        except Exception as e:
            logger.warning("[detection] postprocess error: %s", e)
            continue

        boxes = det_dict["detection_boxes"]
        classes = det_dict["detection_classes"]
        scores = det_dict["detection_scores"]
        h, w = frame.shape[0], frame.shape[1]
        payload = []
        person_detected = False
        for i in range(len(boxes)):
            xmin, ymin, xmax, ymax = boxes[i]
            label = labels[classes[i]] if classes[i] < len(labels) else str(classes[i])
            if label.lower() in ['person', 'human']:
                person_detected = True
            payload.append({
                "bbox": [xmin / w, ymin / h, xmax / w, ymax / h],
                "label": label,
                "confidence": float(scores[i]),
            })
        
        if person_detected:
            trigger_person_alert()
        
        with _latest_detections_lock:
            _latest_detections[:] = payload
        if _detection_loop:
            _detection_loop.call_soon_threadsafe(_schedule_broadcast)

    if infer is not None:
        try:
            infer.close()
        except Exception:
            pass
    logger.info("[detection] worker stopped")


def _raw_to_per_class_list(raw):
    """Convert single NMS-style buffer (N, 6) to list of per-class arrays (each M, 5) for extract_detections."""
    import numpy as np
    raw = np.asarray(raw)
    if raw.size == 0:
        return []
    if raw.ndim == 1:
        raw = raw.reshape(1, -1)
    # Assume shape (num_det, 6) with [x1,y1,x2,y2,class_id,score] or similar
    if raw.shape[-1] >= 6:
        # columns: often x1,y1,x2,y2,class_id,score
        max_cls = int(raw[:, 4].max()) + 1 if raw.shape[0] > 0 else 1
        out = [[] for _ in range(max(80, max_cls))]
        for i in range(raw.shape[0]):
            row = raw[i]
            cid = int(row[4])
            score = float(row[5])
            # bbox in row[:4] - order may be x1,y1,x2,y2
            out[cid].append([float(row[0]), float(row[1]), float(row[2]), float(row[3]), score])
        return [np.array(x, dtype=np.float32) if len(x) else np.zeros((0, 5), dtype=np.float32) for x in out]
    return [raw]


async def _broadcast_detections():
    with _latest_detections_lock:
        data = list(_latest_detections)
    msg = json.dumps({"type": "detections", "data": data})
    with _detection_ws_lock:
        conns = list(_detection_ws_set)
    for ws in conns:
        try:
            await ws.send_text(msg)
        except Exception:
            pass


def _schedule_broadcast():
    """Called from main loop (thread-safe): schedule async broadcast."""
    if _detection_loop is None:
        return
    asyncio.run_coroutine_threadsafe(_broadcast_detections(), _detection_loop)

def get_cpu_temp():
    try:
        temps = psutil.sensors_temperatures()
        # Common keys for Pi: 'cpu_thermal' or 'rp1_adc'
        if 'cpu_thermal' in temps and temps['cpu_thermal']:
            return temps['cpu_thermal'][0].current
        if 'rp1_adc' in temps and temps['rp1_adc']:
            return temps['rp1_adc'][0].current
        # Fallback to any sensor if neither exist
        for k, v in temps.items():
            if v:
                return v[0].current
    except Exception:
        pass
    return 0

@router.get("/camera/list")
async def list_cameras():
    """List all available camera devices."""
    available = []
    for i in range(10):
        try:
            cap = cv2.VideoCapture(i)
            if cap is not None and cap.isOpened():
                width = cap.get(cv2.CAP_PROP_FRAME_WIDTH)
                height = cap.get(cv2.CAP_PROP_FRAME_HEIGHT)
                available.append({
                    "index": i,
                    "width": int(width),
                    "height": int(height),
                    "name": f"USB Camera {i}"
                })
                cap.release()
        except Exception:
            pass
    return {"cameras": available}

@router.post("/camera/select")
async def select_camera(request: dict):
    """Select which camera to use by index."""
    global camera_process
    index = int(request.get("index", 0))
    os.environ["CAMERA_INDEX"] = str(index)
    logger.info(f"Camera index set to {index}")
    
    if camera_process and camera_process.is_alive():
        stop_event.set()
        camera_process.join(timeout=3)
        if camera_process.is_alive():
            camera_process.terminate()
        camera_process = None
    
    return {"status": "success", "index": index}

@router.get("/system/stats")
async def get_stats():
    return {
        "time": time.strftime("%I:%M:%S %p"),
        "cpu_percent": psutil.cpu_percent(),
        "memory_percent": psutil.virtual_memory().percent,
        "temperature": get_cpu_temp()
    }

@router.post("/camera/start")
async def start_camera():
    global camera_process, stop_event
    if camera_process and camera_process.is_alive():
        return {"status": "already_running"}
    
    stop_event.clear()
    camera_process = multiprocessing.Process(
        target=run_stream_process,
        args=(stream_queue, stop_event, detection_enabled, detection_queue)
    )
    camera_process.start()
    return {"status": "started"}

@router.post("/camera/stop")
async def stop_camera():
    global camera_process, stop_event
    if camera_process:
        stop_event.set()
        camera_process.join(timeout=2)
        if camera_process.is_alive():
            camera_process.terminate()
        camera_process = None
    return {"status": "stopped"}

def generate_frames():
    while True:
        try:
            frame = stream_queue.get(timeout=1.0)
        except Exception:
            if camera_process and not camera_process.is_alive():
                break
            continue
            
        if frame is None:
            break
        
        frame = cv2.rotate(frame, cv2.ROTATE_90_CLOCKWISE)
        frame = cv2.resize(frame, (480, 800), interpolation=cv2.INTER_LINEAR)
        
        frame_bgr = cv2.cvtColor(frame, cv2.COLOR_RGB2BGR)
        ret, buffer = cv2.imencode('.jpg', frame_bgr)
        frame_bytes = buffer.tobytes()
        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + frame_bytes + b'\r\n')

@router.get("/video_feed")
async def video_feed():
    return StreamingResponse(generate_frames(), media_type="multipart/x-mixed-replace; boundary=frame")

@router.post("/camera/capture")
async def capture_image():
    try:
        frame = stream_queue.get(timeout=2.0)
        frame = cv2.rotate(frame, cv2.ROTATE_90_CLOCKWISE)
        frame = cv2.resize(frame, (480, 800), interpolation=cv2.INTER_LINEAR)
        
        timestamp = int(time.time())
        filename = f"capture_{timestamp}.jpg"
        save_path = os.path.join("captures", filename)
        os.makedirs("captures", exist_ok=True)
        
        frame_bgr = cv2.cvtColor(frame, cv2.COLOR_RGB2BGR)
        cv2.imwrite(save_path, frame_bgr)
        logger.info("Captured: %s", save_path)
        return {"status": "success", "filename": filename}
    except Exception as e:
        import traceback
        traceback.print_exc()
        return {"status": "error", "message": f"Capture failed: {str(e)}"}

@router.post("/camera/detection/start")
async def start_detection():
    global _detection_loop, _detection_worker_thread
    detection_enabled.value = True
    _detection_loop = asyncio.get_running_loop()
    if _detection_worker_thread is None or not _detection_worker_thread.is_alive():
        _detection_worker_stop.clear()
        _detection_worker_thread = threading.Thread(target=_run_detection_worker, daemon=True)
        _detection_worker_thread.start()
    return {"status": "started"}


@router.post("/camera/detection/stop")
async def stop_detection():
    detection_enabled.value = False
    return {"status": "stopped"}

@router.get("/gallery/images")
async def list_gallery_images():
    files = glob.glob("captures/*.jpg")
    files.sort(key=os.path.getmtime, reverse=True)
    images = []
    for f in files:
        filename = os.path.basename(f)
        images.append({
            "filename": filename,
            "url": f"/captures/{filename}"
        })
    return {"status": "success", "images": images}

@router.delete("/gallery/images/{filename}")
async def delete_gallery_image(filename: str):
    file_path = os.path.join("captures", filename)
    if os.path.exists(file_path):
        try:
            os.remove(file_path)
            return {"status": "success"}
        except Exception as e:
            return {"status": "error", "message": str(e)}
    return {"status": "error", "message": "File not found"}

@router.websocket("/ws/detections")
async def detection_websocket(websocket: WebSocket):
    await websocket.accept()
    global _detection_loop
    if _detection_loop is None:
        _detection_loop = asyncio.get_running_loop()
    with _detection_ws_lock:
        _detection_ws_set.add(websocket)
    logger.info("Detection WebSocket connected")
    try:
        while True:
            try:
                await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
            except asyncio.TimeoutError:
                await websocket.send_text(json.dumps({"type": "ping"}))
    except WebSocketDisconnect:
        pass
    finally:
        with _detection_ws_lock:
            _detection_ws_set.discard(websocket)
        logger.info("Detection WebSocket disconnected")
