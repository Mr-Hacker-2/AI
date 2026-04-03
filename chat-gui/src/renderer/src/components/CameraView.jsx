import React, { useEffect, useState, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { ArrowLeft, RefreshCw, AlertCircle, Image as GalleryIcon, Camera, Scan } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { API_BASE_URL, WS_BASE_URL } from '../config.js';

const pendingStopTimeoutRef = { current: null };
const STOP_DELAY_MS = 500;

const STREAM_IMAGE_WIDTH = 480;
const STREAM_IMAGE_HEIGHT = 800;
const STREAM_ASPECT = STREAM_IMAGE_WIDTH / STREAM_IMAGE_HEIGHT;

export default function CameraView() {
    const navigate = useNavigate();
    const [status, setStatus] = useState('connecting');
    const [detections, setDetections] = useState([]);
    const [detectionActive, setDetectionActive] = useState(false);
    const [detectionError, setDetectionError] = useState(null);
    const [flash, setFlash] = useState(false);
    const [cameras, setCameras] = useState([]);
    const [selectedCamera, setSelectedCamera] = useState(null);
    const [showCameraSelector, setShowCameraSelector] = useState(false);
    const wsRef = useRef(null);
    const videoContainerRef = useRef(null);
    const [containerSize, setContainerSize] = useState({ width: 1, height: 1 });

    const videoFeedUrl = `${API_BASE_URL}/video_feed`;
    const wsUrl = `${WS_BASE_URL}/ws/detections`;
    const startUrl = `${API_BASE_URL}/camera/start`;
    const stopUrl = `${API_BASE_URL}/camera/stop`;
    const detectionStartUrl = `${API_BASE_URL}/camera/detection/start`;
    const detectionStopUrl = `${API_BASE_URL}/camera/detection/stop`;
    const captureUrl = `${API_BASE_URL}/camera/capture`;
    const listCamerasUrl = `${API_BASE_URL}/camera/list`;
    const selectCameraUrl = `${API_BASE_URL}/camera/select`;

    useEffect(() => {
        let isMounted = true;
        const sessionId = Math.random().toString(36).substring(7);

        const startCamera = async () => {
            try {
                console.log(`Starting camera session: ${sessionId}`);
                const res = await fetch(startUrl, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ session_id: sessionId })
                });
                if (res.ok) {
                    if (pendingStopTimeoutRef.current) {
                        clearTimeout(pendingStopTimeoutRef.current);
                        pendingStopTimeoutRef.current = null;
                    }
                    setStatus('connected');
                    console.log("Camera started");
                } else {
                    const err = await res.json().catch(() => ({}));
                    console.error("Camera start failed:", err.message || res.status);
                    if (isMounted) setStatus('error');
                }
            } catch (error) {
                console.error("Failed to start camera:", error);
                if (isMounted) setStatus('error');
            }
        };

        const connectWebSocket = () => {
            console.log('Connecting to WebSocket:', wsUrl);
            const ws = new WebSocket(wsUrl);
            wsRef.current = ws;

            ws.onopen = () => {
                if (isMounted) console.log('WebSocket connected (detections)');
            };

            ws.onmessage = (event) => {
                try {
                    const message = JSON.parse(event.data);
                    if (message.type === 'detections' && isMounted) {
                        setDetections(Array.isArray(message.data) ? message.data : []);
                    }
                } catch (e) {
                    console.error('Error parsing WebSocket message:', e);
                }
            };

            ws.onerror = (error) => {
                console.error('WebSocket error:', error);
                if (isMounted) setStatus('error');
            };

            ws.onclose = () => {
                console.log('WebSocket disconnected (detections may stop)');
            };
        };

        startCamera().then(() => {
            connectWebSocket();
        });

        return () => {
            isMounted = false;
            if (wsRef.current) {
                wsRef.current.close();
            }

            const sendStop = () => {
                fetch(detectionStopUrl, {
                    method: 'POST',
                    keepalive: true,
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ session_id: sessionId })
                }).catch(console.error);
                fetch(stopUrl, {
                    method: 'POST',
                    keepalive: true,
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ session_id: sessionId })
                }).catch(console.error);
            };

            if (pendingStopTimeoutRef.current) {
                clearTimeout(pendingStopTimeoutRef.current);
            }
            pendingStopTimeoutRef.current = setTimeout(() => {
                pendingStopTimeoutRef.current = null;
                sendStop();
            }, STOP_DELAY_MS);
        };
    }, []);

    useEffect(() => {
        const el = videoContainerRef.current;
        if (!el) return;
        const updateSize = () => {
            const { width, height } = el.getBoundingClientRect();
            setContainerSize({ width, height });
        };
        updateSize();
        const ro = new ResizeObserver((entries) => {
            if (!entries.length) return;
            const { width, height } = entries[0].contentRect;
            setContainerSize({ width, height });
        });
        ro.observe(el);
        return () => ro.disconnect();
    }, []);

    const refreshCameras = async () => {
        try {
            const res = await fetch(listCamerasUrl);
            const data = await res.json();
            setCameras(data.cameras || []);
            if (data.cameras && data.cameras.length > 0 && !selectedCamera) {
                setSelectedCamera(data.cameras[0].index);
            }
        } catch (e) {
            console.error('Failed to list cameras:', e);
        }
    };

    const selectCamera = async (index) => {
        try {
            await fetch(selectCameraUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ index })
            });
            setSelectedCamera(index);
            setShowCameraSelector(false);
            window.location.reload();
        } catch (e) {
            console.error('Failed to select camera:', e);
        }
    };

    const toggleDetection = async () => {
        setDetectionError(null);
        if (detectionActive) {
            setDetectionActive(false);
            setDetections([]);
            try {
                await fetch(detectionStopUrl, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ session_id: 'default' })
                });
            } catch (e) {
                console.error('Failed to stop detection:', e);
            }
        } else {
            try {
                const res = await fetch(detectionStartUrl, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ session_id: 'default' })
                });
                const data = await res.json().catch(() => ({}));
                if (data.status === 'started') {
                    setDetectionActive(true);
                } else {
                    const msg = data.message || data.error || 'Detection failed to start';
                    setDetectionError(msg);
                    console.error('Detection start failed:', msg);
                }
            } catch (e) {
                const msg = e.message || 'Network error';
                setDetectionError(msg);
                console.error('Failed to start detection:', e);
            }
        }
    };

    const captureFrame = async () => {
        setFlash(true);
        setTimeout(() => setFlash(false), 150);

        try {
            const res = await fetch(captureUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ session_id: 'default' })
            });
            const data = await res.json();
            if (data.status === 'success') {
                console.log('Image captured:', data.filename);
            } else {
                console.error('Capture failed:', data.message);
            }
        } catch (error) {
            console.error('Error capturing frame:', error);
        }
    };

    const imageNormToContainerNorm = (xImgNorm, yImgNorm) => {
        const { width: cw, height: ch } = containerSize;
        if (cw <= 0 || ch <= 0) return { x: xImgNorm, y: yImgNorm };
        const scale = Math.max(cw / STREAM_IMAGE_WIDTH, ch / STREAM_IMAGE_HEIGHT);
        const displayedW = STREAM_IMAGE_WIDTH * scale;
        const displayedH = STREAM_IMAGE_HEIGHT * scale;
        const offsetLeft = (cw - displayedW) / 2;
        const offsetTop = (ch - displayedH) / 2;
        const xContainer = (offsetLeft + xImgNorm * displayedW) / cw;
        const yContainer = (offsetTop + yImgNorm * displayedH) / ch;
        return { x: xContainer, y: yContainer };
    };

    const renderBoundingBoxes = () => {
        const { width: cw, height: ch } = containerSize;
        if (cw < 10 || ch < 10) return null;

        return detections.map((det, index) => {
            const [oxMin, oyMin, oxMax, oyMax] = det.bbox;
            const sxMin = 1 - oyMax;
            const syMin = oxMin;
            const sxMax = 1 - oyMin;
            const syMax = oxMax;

            const tl = imageNormToContainerNorm(sxMin, syMin);
            const br = imageNormToContainerNorm(sxMax, syMax);
            const left = Math.max(0, Math.min(1, tl.x));
            const top = Math.max(0, Math.min(1, tl.y));
            const right = Math.max(0, Math.min(1, br.x));
            const bottom = Math.max(0, Math.min(1, br.y));

            const leftPct = `${left * 100}%`;
            const topPct = `${top * 100}%`;
            const widthPct = `${Math.max(0, (right - left) * 100)}%`;
            const heightPct = `${Math.max(0, (bottom - top) * 100)}%`;

            const borderColor = 'rgba(0, 255, 255, 1)';

            return (
                <div
                    key={index}
                    className="absolute border-2 flex flex-col items-start justify-start pointer-events-none"
                    style={{
                        left: leftPct,
                        top: topPct,
                        width: widthPct,
                        height: heightPct,
                        borderColor,
                        boxShadow: '0 0 10px rgba(0,255,255,0.3)'
                    }}
                >
                    <div
                        className="bg-cyan-500 text-black text-[10px] font-bold px-2 py-0.5 rounded-lg"
                        style={{ marginTop: '-20px' }}
                    >
                        {det.label} {Math.round(det.confidence * 100)}%
                    </div>
                </div>
            );
        });
    };

    return (
        <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="relative w-full h-full overflow-hidden bg-black"
        >
            <AnimatePresence>
                {flash && (
                    <motion.div
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        exit={{ opacity: 0 }}
                        transition={{ duration: 0.05 }}
                        className="absolute inset-0 z-[100] bg-white pointer-events-none"
                    />
                )}
            </AnimatePresence>

            <div className="absolute top-0 left-0 right-0 z-50 p-6 flex justify-between items-start pointer-events-none">
                <button
                    onClick={() => navigate('/')}
                    className="pointer-events-auto p-3 rounded-2xl flex items-center justify-center bg-black/40 backdrop-blur-md border border-white/20 text-white hover:bg-white hover:text-black transition-all duration-200 shadow-lg"
                >
                    <ArrowLeft size={24} />
                </button>

                <div className="flex flex-col items-end pointer-events-auto gap-2">
                    <button
                        onClick={() => { refreshCameras(); setShowCameraSelector(true); }}
                        className="pointer-events-auto p-2 rounded-xl flex items-center justify-center bg-black/40 backdrop-blur-md border border-white/20 text-white hover:bg-white/20 transition-all"
                        title="Select Camera"
                    >
                        <Camera size={20} />
                    </button>
                    {status === 'connecting' && (
                        <div className="flex items-center gap-2 px-4 py-2 bg-black/60 backdrop-blur border border-white/20 rounded-full text-xs text-white font-['Plus_Jakarta_Sans'] animate-pulse">
                            <RefreshCw size={14} className="animate-spin" />
                            <span>Connecting</span>
                        </div>
                    )}
                    {status === 'error' && (
                        <div className="flex items-center gap-2 px-4 py-2 bg-red-500/80 backdrop-blur border border-red-400 rounded-full text-xs text-white font-['Plus_Jakarta_Sans']">
                            <AlertCircle size={14} />
                            <span>Offline</span>
                        </div>
                    )}
                </div>
            </div>

            <div ref={videoContainerRef} className="absolute inset-0 z-0 flex items-center justify-center bg-black">
                <img
                    src={videoFeedUrl}
                    className="w-full h-full object-cover"
                    alt="Live Camera Feed"
                    onLoad={() => setStatus((s) => (s === 'connecting' ? 'connected' : s))}
                    onError={(e) => {
                        console.error("Video feed error", e);
                        setStatus('error');
                    }}
                />

                <div className="absolute inset-0 pointer-events-none z-10">
                    {detectionActive && renderBoundingBoxes()}
                </div>

                {status === 'error' && (
                    <div className="absolute inset-0 z-20 flex flex-col items-center justify-center bg-black/80 backdrop-blur-sm">
                        <div className="p-8 rounded-3xl bg-black/60 backdrop-blur border border-red-500/50 flex flex-col items-center gap-4 shadow-2xl">
                            <AlertCircle size={56} className="text-red-500" />
                            <p className="text-red-500 font-['Syne'] font-bold text-lg">Camera Offline</p>
                            <button
                                onClick={() => window.location.reload()}
                                className="ai-btn bg-red-500 text-white px-8 py-3 rounded-2xl hover:bg-red-600 transition-all shadow-lg shadow-red-500/25"
                            >
                                Retry
                            </button>
                        </div>
                    </div>
                )}
            </div>

            <div className="absolute bottom-0 left-0 right-0 p-8 pb-10 flex justify-between items-end z-50 bg-gradient-to-t from-black/80 via-black/40 to-transparent h-48 pointer-events-none">
                <button
                    onClick={() => navigate('/gallery')}
                    className="pointer-events-auto flex flex-col items-center gap-2 group transition-transform active:scale-95"
                >
                    <div className="w-16 h-16 bg-black/40 backdrop-blur-md border border-white/20 rounded-2xl flex items-center justify-center group-hover:bg-white/20 group-hover:border-white transition-all shadow-lg">
                        <GalleryIcon size={28} className="text-white" />
                    </div>
                    <span className="text-[10px] font-['Plus_Jakarta_Sans'] text-white/80 tracking-wider">Gallery</span>
                </button>

                <button
                    onClick={captureFrame}
                    className="pointer-events-auto relative group transition-transform active:scale-95 mx-auto -translate-y-2"
                    aria-label="Capture"
                >
                    <div className="w-24 h-24 rounded-full border-[4px] border-white bg-transparent flex items-center justify-center shadow-2xl">
                        <div className="w-20 h-20 rounded-full bg-white group-active:scale-90 transition-transform duration-100 shadow-[inset_0_-4px_8px_rgba(0,0,0,0.1)]" />
                    </div>
                </button>

                <button
                    onClick={toggleDetection}
                    title={detectionActive ? 'Stop object detection' : 'Start object detection'}
                    className={`pointer-events-auto flex flex-col items-center gap-2 group transition-transform active:scale-95 ${detectionActive ? 'opacity-100' : 'opacity-80'}`}
                >
                    <div className={`w-16 h-16 rounded-2xl flex items-center justify-center border border-white/20 transition-all shadow-lg ${
                        detectionActive 
                            ? 'bg-cyan-500 shadow-cyan-500/30' 
                            : 'bg-black/40 backdrop-blur-md group-hover:bg-white/20'
                    }`}>
                        <Scan size={28} className={detectionActive ? 'text-white' : 'text-white'} />
                    </div>
                    <span className="text-[10px] font-['Plus_Jakarta_Sans'] text-white/80 tracking-wider">
                        {detectionActive ? 'Detect On' : 'Detect'}
                    </span>
                    {detectionError && <span className="text-[8px] text-red-400 max-w-[80px] truncate">{detectionError}</span>}
                </button>
            </div>

            <AnimatePresence>
                {showCameraSelector && (
                    <motion.div
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        exit={{ opacity: 0 }}
                        className="fixed inset-0 z-[100] flex items-center justify-center bg-black/70"
                        onClick={() => setShowCameraSelector(false)}
                    >
                        <motion.div
                            initial={{ scale: 0.9 }}
                            animate={{ scale: 1 }}
                            exit={{ scale: 0.9 }}
                            className="bg-gray-900 border border-white/20 rounded-2xl p-6 max-w-sm w-full mx-4"
                            onClick={e => e.stopPropagation()}
                        >
                            <h3 className="text-white font-semibold mb-4">Select Camera</h3>
                            {cameras.length === 0 ? (
                                <p className="text-gray-400 text-sm">No cameras found. Check USB connection.</p>
                            ) : (
                                <div className="space-y-2">
                                    {cameras.map(cam => (
                                        <button
                                            key={cam.index}
                                            onClick={() => selectCamera(cam.index)}
                                            className={`w-full p-3 rounded-xl text-left transition-all ${
                                                selectedCamera === cam.index
                                                    ? 'bg-purple-600 text-white'
                                                    : 'bg-gray-800 text-gray-300 hover:bg-gray-700'
                                            }`}
                                        >
                                            <div className="font-medium">{cam.name}</div>
                                            <div className="text-xs opacity-70">{cam.width}x{cam.height}</div>
                                        </button>
                                    ))}
                                </div>
                            )}
                            <button
                                onClick={() => setShowCameraSelector(false)}
                                className="w-full mt-4 p-3 rounded-xl bg-gray-800 text-gray-300 hover:bg-gray-700"
                            >
                                Cancel
                            </button>
                        </motion.div>
                    </motion.div>
                )}
            </AnimatePresence>
        </motion.div>
    );
}
