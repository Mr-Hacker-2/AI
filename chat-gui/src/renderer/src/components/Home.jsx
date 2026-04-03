import React from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { MessageCircle, Settings, Camera, Image as GalleryIcon, Code, Map, Bot, Cloud, MapPin, Search, Gamepad2, Shield, Siren, Lock, Unlock, Terminal, Folder, CreditCard } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import Avatar from './Avatar';
import { useWebSocket } from '../contexts/WebSocketContext.jsx';
import { useRef, useState, useEffect } from 'react';

const AI_COLOR = '#7c3aed';
const AI_BG    = 'rgba(124, 58, 237, .12)';
const AI_SEND  = 'linear-gradient(135deg, #7c3aed, #6d28d9)';

const MenuButton = ({ icon: Icon, label, onClick, color }) => (
  <motion.button
    whileHover={{ scale: 1.05, y: -2 }}
    whileTap={{ scale: 0.95 }}
    onClick={onClick}
    style={{
      width: '100%',
      minHeight: 100,
      flex: 1,
      minWidth: 0,
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      gap: 10,
      border: '1.5px solid var(--border)',
      borderRadius: 20,
      background: 'var(--surface)',
      color: color,
      cursor: 'pointer',
      fontFamily: 'var(--font-body)',
      transition: 'all .2s',
      boxShadow: '0 2px 12px rgba(0,0,0,.06)',
    }}
  >
    <Icon size={36} />
    <span style={{ fontSize: '.75rem', fontWeight: 600, letterSpacing: '.04em' }}>{label}</span>
  </motion.button>
);

export default function Home() {
  const navigate = useNavigate();
  const {
    toggleVoice,
    startVosk,
    stopVosk,
    isRecording,
    isVoskRecording,
    voiceStatus,
    voskText,
    voiceStreamText,
    isVoiceStreaming,
    messages
  } = useWebSocket();

  const [showBubble, setShowBubble] = useState(false);
  const [customExpression, setCustomExpression] = useState(null);
  const [emotionHistory, setEmotionHistory] = useState([]);
  const [lastUserMessage, setLastUserMessage] = useState('');
  const [lastAIMessage, setLastAIMessage] = useState('');
  const bubbleTimeoutRef = useRef(null);

  useEffect(() => {
    if (voiceStatus === 'speaking' && isVoiceStreaming) {
      const text = voiceStreamText.toLowerCase();
      const hasExclamation = text.includes('!');
      const hasQuestion = text.includes('?');
      
      setLastAIMessage(text);
      
      const detectEmotion = (fullText) => {
        const lowered = fullText.toLowerCase();
        
        const greetings = ['hello', 'hi', 'hey', 'good morning', 'good evening', 'good afternoon', "what's up", 'howdy', 'greetings', 'good to see you', 'nice to meet'];
        const excitedWords = ['wow', 'amazing', 'incredible', 'unbelievable', 'omg', 'oh my god', 'no way', "can't wait", 'super', 'epic', 'holy', 'insane', 'crazy'];
        const happyWords = ['great', 'awesome', 'wonderful', 'fantastic', 'love', 'thank', 'thanks', 'please', 'happy', 'nice', 'good job', 'well done', 'congratulations', 'yay', 'cool', 'brilliant', 'perfect', 'excellent', 'good', 'appreciate', 'helpful'];
        const angryWords = ['angry', 'mad', 'hate', 'stupid', 'idiot', 'worst', 'terrible', 'horrible', 'annoying', 'frustrat', 'annoyed', 'furious', 'irritat', 'upset', 'annoying', 'upset', 'unacceptable', 'pathetic'];
        const sadWords = ['sad', 'sorry', 'unfortunately', 'miss', 'lonely', 'upset', 'feeling bad', 'depressed', 'crying', 'tears', 'hurt', 'broken', 'heart', 'unfortunately', 'devastat'];
        const surpriseWords = ['surprise', 'shock', 'unexpected', 'wait what', 'no way', 'really', 'unexpected', 'wait a minute', 'hold on'];
        const fearWords = ['scared', 'afraid', 'worried', 'nervous', 'anxious', 'fear', 'panic', 'terrify', 'concern', 'concerned', 'danger'];
        const cuteWords = ['cute', 'adorable', 'sweet', 'precious', 'baby', 'kitten', 'puppy', 'fluffy', '萌', 'kawaii', 'precious'];
        const complimentWords = ['beautiful', 'pretty', 'handsome', 'gorgeous', 'lovely', 'charming', 'wonderful', 'stunning', ' attractive'];
        const commandWords = ['do this', 'make it', 'start', 'stop', 'turn on', 'turn off', 'run', 'execute', 'open', 'close'];
        const yesWords = ['yes', 'yeah', 'sure', 'okay', 'ok', 'correct', 'right', 'definitely', 'absolutely', 'indeed', 'do it', 'trigger', 'go ahead'];
        const noWords = ['no', 'nope', 'not', 'never', 'nothing', 'don\'t'];
        const helpWords = ['help', 'need', 'can you', 'please help', 'could you', 'would you', 'assist', 'support'];
        
        if (helpWords.some(w => lowered.includes(w))) {
          return { emotion: 'listening', score: 0.9 };
        }
        if (greetings.some(w => lowered.includes(w))) {
          return { emotion: 'happy', score: 0.95 };
        }
        if (excitedWords.some(w => lowered.includes(w)) && hasExclamation) {
          return { emotion: 'excited', score: 0.95 };
        }
        if (cuteWords.some(w => lowered.includes(w))) {
          return { emotion: 'excited', score: 0.9 };
        }
        if (angryWords.some(w => lowered.includes(w))) {
          return { emotion: 'angry', score: 0.9 };
        }
        if (sadWords.some(w => lowered.includes(w))) {
          return { emotion: 'sad', score: 0.9 };
        }
        if (surpriseWords.some(w => lowered.includes(w))) {
          return { emotion: 'surprised', score: 0.85 };
        }
        if (fearWords.some(w => lowered.includes(w))) {
          return { emotion: 'worried', score: 0.85 };
        }
        if (complimentWords.some(w => lowered.includes(w))) {
          return { emotion: 'shy', score: 0.85 };
        }
        if (commandWords.some(w => lowered.includes(w))) {
          return { emotion: 'listening', score: 0.8 };
        }
        if (yesWords.some(w => lowered === w || lowered.startsWith(w + ' ') || lowered.endsWith(' ' + w) || lowered.includes(' ' + w + ' '))) {
          if (lastAIMessage.includes('alarm')) {
            fetch('http://localhost:8000/security/manual_alarm', { method: 'POST' }).catch(console.error);
            return { emotion: 'angry', score: 1.0 };
          }
          return { emotion: 'happy', score: 0.75 };
        }
        if (noWords.some(w => lowered === w || lowered.startsWith(w) || lowered.includes(' ' + w + ' '))) {
          if (lastAIMessage.includes('alarm')) {
            return { emotion: 'sad', score: 0.6 };
          }
          return { emotion: 'curious', score: 0.7 };
        }
        if (happyWords.some(w => lowered.includes(w))) {
          return { emotion: 'happy', score: 0.7 };
        }
        if (hasQuestion) {
          return { emotion: 'curious', score: 0.8 };
        }
        if (hasExclamation) {
          return { emotion: 'excited', score: 0.65 };
        }
        return { emotion: null, score: 0 };
      };
      
      const combinedText = lastUserMessage + ' ' + text;
      const { emotion, score } = detectEmotion(combinedText);
      
      if (emotion) {
        setCustomExpression(emotion);
        setEmotionHistory(prev => [...prev.slice(-4), { emotion, score, timestamp: Date.now() }]);
      }
    } else if (voiceStatus === 'listening') {
      setCustomExpression('listening');
    } else if (voiceStatus === 'thinking') {
      setCustomExpression('thinking');
    } else {
      setCustomExpression(null);
    }
  }, [voiceStatus, isVoiceStreaming, voiceStreamText, lastUserMessage, lastAIMessage]);

  useEffect(() => {
    if (messages && messages.length > 0) {
      const lastMsg = messages[messages.length - 1];
      if (lastMsg.role === 'user' && lastMsg.text) {
        setLastUserMessage(lastMsg.text);
      }
    }
  }, [messages]);

  const getRobotMood = () => {
    if (emotionHistory.length < 2) return 'neutral';
    const recent = emotionHistory.slice(-3);
    const avgScore = recent.reduce((sum, e) => sum + e.score, 0) / recent.length;
    const emotions = recent.map(e => e.emotion);
    if (emotions.includes('excited') && avgScore > 0.7) return 'veryHappy';
    if (emotions.includes('happy') && avgScore > 0.6) return 'happy';
    if (emotions.includes('angry')) return 'annoyed';
    if (emotions.includes('sad')) return 'concerned';
    return 'neutral';
  };

  useEffect(() => {
    const active = isVoiceStreaming || voiceStatus === 'speaking';
    if (active) {
      if (bubbleTimeoutRef.current) clearTimeout(bubbleTimeoutRef.current);
      setShowBubble(true);
    } else if (showBubble) {
      bubbleTimeoutRef.current = setTimeout(() => {
        setShowBubble(false);
      }, 1000);
    }
    return () => {
      if (bubbleTimeoutRef.current) clearTimeout(bubbleTimeoutRef.current);
    };
  }, [isVoiceStreaming, voiceStatus, showBubble]);

  const displayVoiceText = voiceStreamText.trim();

  // Weather modal state
  const [showWeatherModal, setShowWeatherModal] = useState(false);
  const [weatherData, setWeatherData] = useState(null);
  const [weatherLoading, setWeatherLoading] = useState(false);
  const [weatherError, setWeatherError] = useState(null);
  const [locationInput, setLocationInput] = useState('');

  // Games modal state
  const [showGamesModal, setShowGamesModal] = useState(false);
  const [gamesList, setGamesList] = useState([]);
  const [gamesLoading, setGamesLoading] = useState(false);

  // Security modal state
  const [showSecurityModal, setShowSecurityModal] = useState(false);
  const [securityStatus, setSecurityStatus] = useState('disarmed');
  const [securityLoading, setSecurityLoading] = useState(false);
  const [defusePassword, setDefusePassword] = useState('');
  const [defuseError, setDefuseError] = useState('');

  // Banking modal state
  const [showBankingModal, setShowBankingModal] = useState(false);
  const [bankAccounts, setBankAccounts] = useState(null);
  const [bankLoading, setBankLoading] = useState(false);
  const [newTransaction, setNewTransaction] = useState({ amount: '', description: '', type: 'debit', category: 'Other' });
  const [newOwing, setNewOwing] = useState({ person: '', amount: '', reason: '' });
  const [newOwedToMe, setNewOwedToMe] = useState({ person: '', amount: '', reason: '' });
  const [newBill, setNewBill] = useState({ name: '', amount: '', due_date: '', category: 'Other' });
  const [newSavingsGoal, setNewSavingsGoal] = useState({ name: '', target: '', icon: '💰' });
  const [activeTab, setActiveTab] = useState('accounts');

  const fetchSecurityStatus = async () => {
    try {
      const resp = await fetch('http://localhost:8000/security/status');
      const data = await resp.json();
      setSecurityStatus(data.status || 'disarmed');
    } catch (err) {
      console.error('Failed to fetch security status:', err);
    }
  };

  const triggerAlarm = async () => {
    setSecurityLoading(true);
    try {
      await fetch('http://localhost:8000/security/manual_alarm', { method: 'POST' });
      setSecurityStatus('alarm');
    } catch (err) {
      console.error('Failed to trigger alarm:', err);
    } finally {
      setSecurityLoading(false);
    }
  };

  const defuseAlarm = async (e) => {
    e.preventDefault();
    setDefuseError('');
    try {
      const resp = await fetch('http://localhost:8000/security/defuse', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: defusePassword })
      });
      const data = await resp.json();
      if (data.status === 'defused') {
        setSecurityStatus('disarmed');
        setDefusePassword('');
      } else {
        setDefuseError(data.message || 'Incorrect password');
      }
    } catch (err) {
      setDefuseError('Connection error');
    }
  };

  const fetchGames = async () => {
    setGamesLoading(true);
    try {
      const resp = await fetch('http://localhost:8000/games');
      const data = await resp.json();
      setGamesList(data.games || []);
    } catch (err) {
      console.error('Failed to load games:', err);
    } finally {
      setGamesLoading(false);
    }
  };

  const launchGame = async (game) => {
    try {
      await fetch('http://localhost:8000/games/launch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ game_id: game.id, executable: game.executable })
      });
    } catch (err) {
      console.error('Failed to launch game:', err);
    }
  };

  const fetchBankAccounts = async () => {
    setBankLoading(true);
    try {
      const resp = await fetch('http://localhost:8000/banking/accounts');
      const data = await resp.json();
      setBankAccounts(data);
    } catch (err) {
      console.error('Failed to fetch bank accounts:', err);
    } finally {
      setBankLoading(false);
    }
  };

  const addTransaction = async (e) => {
    e.preventDefault();
    if (!newTransaction.amount || !newTransaction.description) return;
    try {
      await fetch('http://localhost:8000/banking/transaction', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          amount: parseFloat(newTransaction.amount),
          description: newTransaction.description,
          type: newTransaction.type,
          account: "My Checking",
          category: newTransaction.category || "Other"
        })
      });
      setNewTransaction({ amount: '', description: '', type: 'debit', category: 'Other' });
      fetchBankAccounts();
    } catch (err) {
      console.error('Failed to add transaction:', err);
    }
  };

  const handleBankingClick = () => {
    setShowBankingModal(true);
    fetchBankAccounts();
  };

  const addOwing = async (e) => {
    e.preventDefault();
    if (!newOwing.person || !newOwing.amount || !newOwing.reason) return;
    try {
      await fetch('http://localhost:8000/banking/owing', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          person: newOwing.person,
          amount: parseFloat(newOwing.amount),
          reason: newOwing.reason
        })
      });
      setNewOwing({ person: '', amount: '', reason: '' });
      fetchBankAccounts();
    } catch (err) {
      console.error('Failed to add owing:', err);
    }
  };

  const deleteOwing = async (id) => {
    try {
      await fetch(`http://localhost:8000/banking/owing/${id}`, { method: 'DELETE' });
      fetchBankAccounts();
    } catch (err) {
      console.error('Failed to delete owing:', err);
    }
  };

  const addOwedToMe = async (e) => {
    e.preventDefault();
    if (!newOwedToMe.person || !newOwedToMe.amount || !newOwedToMe.reason) return;
    try {
      await fetch('http://localhost:8000/banking/owed_to_me', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          person: newOwedToMe.person,
          amount: parseFloat(newOwedToMe.amount),
          reason: newOwedToMe.reason
        })
      });
      setNewOwedToMe({ person: '', amount: '', reason: '' });
      fetchBankAccounts();
    } catch (err) {
      console.error('Failed to add owed to me:', err);
    }
  };

  const deleteOwedToMe = async (id) => {
    try {
      await fetch(`http://localhost:8000/banking/owed_to_me/${id}`, { method: 'DELETE' });
      fetchBankAccounts();
    } catch (err) {
      console.error('Failed to delete owed to me:', err);
    }
  };

  const addBill = async (e) => {
    e.preventDefault();
    if (!newBill.name || !newBill.amount || !newBill.due_date) return;
    try {
      await fetch('http://localhost:8000/banking/bills', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: newBill.name,
          amount: parseFloat(newBill.amount),
          due_date: newBill.due_date,
          category: newBill.category
        })
      });
      setNewBill({ name: '', amount: '', due_date: '', category: 'Other' });
      fetchBankAccounts();
    } catch (err) {
      console.error('Failed to add bill:', err);
    }
  };

  const toggleBillPaid = async (id) => {
    try {
      await fetch(`http://localhost:8000/banking/bills/${id}`, { method: 'PUT' });
      fetchBankAccounts();
    } catch (err) {
      console.error('Failed to toggle bill:', err);
    }
  };

  const deleteBill = async (id) => {
    try {
      await fetch(`http://localhost:8000/banking/bills/${id}`, { method: 'DELETE' });
      fetchBankAccounts();
    } catch (err) {
      console.error('Failed to delete bill:', err);
    }
  };

  const addSavingsGoal = async (e) => {
    e.preventDefault();
    if (!newSavingsGoal.name || !newSavingsGoal.target) return;
    try {
      await fetch('http://localhost:8000/banking/savings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: newSavingsGoal.name,
          target: parseFloat(newSavingsGoal.target),
          icon: newSavingsGoal.icon
        })
      });
      setNewSavingsGoal({ name: '', target: '', icon: '💰' });
      fetchBankAccounts();
    } catch (err) {
      console.error('Failed to add savings goal:', err);
    }
  };

  const addToSavingsGoal = async (goalId, amount) => {
    try {
      await fetch(`http://localhost:8000/banking/savings/${goalId}/add`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ amount: parseFloat(amount) })
      });
      fetchBankAccounts();
    } catch (err) {
      console.error('Failed to add to savings goal:', err);
    }
  };

  const deleteSavingsGoal = async (id) => {
    try {
      await fetch(`http://localhost:8000/banking/savings/${id}`, { method: 'DELETE' });
      fetchBankAccounts();
    } catch (err) {
      console.error('Failed to delete savings goal:', err);
    }
  };

  const handleGamesClick = () => {
    setShowGamesModal(true);
    fetchGames();
  };

  const fetchWeather = async (city = null) => {
    setWeatherLoading(true);
    setWeatherError(null);
    try {
      let url = 'http://localhost:8000/weather';
      if (city) {
        url += `?city=${encodeURIComponent(city)}`;
      } else if (navigator.geolocation) {
        // Use geolocation for "My location"
        const pos = await new Promise((resolve, reject) => {
          navigator.geolocation.getCurrentPosition(resolve, reject, { timeout: 5000 });
        });
        url += `?lat=${pos.coords.latitude}&lon=${pos.coords.longitude}`;
      }
      const resp = await fetch(url);
      const data = await resp.json();
      if (data.error) {
        setWeatherError(data.error);
      } else {
        setWeatherData(data);
      }
    } catch (err) {
      setWeatherError(err.message || 'Failed to fetch weather');
    } finally {
      setWeatherLoading(false);
    }
  };

  const handleWeatherClick = () => {
    setShowWeatherModal(true);
    setWeatherData(null);
    setWeatherError(null);
    setLocationInput('');
    // Auto-fetch for "My location" by default
    fetchWeather();
  };

  const handleSearch = (e) => {
    e.preventDefault();
    if (locationInput.trim()) {
      fetchWeather(locationInput.trim());
    }
  };

  const handleMyLocation = () => {
    setLocationInput('');
    fetchWeather();
  };

  const pressTimer = useRef(null);
  const [isHoldMode, setIsHoldMode] = useState(false);

  const handleMouseDown = () => {
    console.log('[Voice] Mouse down, starting timer...');
    setIsHoldMode(false);
    pressTimer.current = setTimeout(() => {
      console.log('[Voice] Long press detected, starting Vosk...');
      setIsHoldMode(true);
      startVosk();
    }, 400);
  };

  const handleMouseUp = () => {
    console.log('[Voice] Mouse up, isHoldMode:', isHoldMode);
    if (pressTimer.current) {
      clearTimeout(pressTimer.current);
      pressTimer.current = null;
    }
    if (isHoldMode) {
      console.log('[Voice] Stopping Vosk...');
      stopVosk();
      setIsHoldMode(false);
    } else {
      console.log('[Voice] Toggle voice (short press)...');
      toggleVoice();
    }
  };

  const handleMouseLeave = () => {
    if (isHoldMode) {
      stopVosk();
      setIsHoldMode(false);
    }
    if (pressTimer.current) {
      clearTimeout(pressTimer.current);
      pressTimer.current = null;
    }
  };

  return (
    <div
      className="relative w-full h-full overflow-hidden flex flex-col items-center justify-center"
      style={{
        background: 'var(--bg)',
        fontFamily: 'var(--font-body)',
        color: 'var(--text)',
      }}
    >
      {/* Ambient background */}
      <div className="ambient-bg" />
      <div className="blob blob-1" />
      <div className="blob blob-2" />

      {/* Settings button top left */}
      <motion.button
        whileHover={{ scale: 1.05 }}
        whileTap={{ scale: 0.95 }}
        onClick={() => navigate('/settings')}
        style={{
          position: 'absolute',
          top: 16,
          left: 16,
          zIndex: 30,
          width: 44,
          height: 44,
          borderRadius: 14,
          border: '1.5px solid var(--border)',
          background: 'rgba(255,255,255,.9)',
          backdropFilter: 'blur(10px)',
          cursor: 'pointer',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          color: AI_COLOR,
          boxShadow: '0 2px 12px rgba(0,0,0,.08)',
          transition: 'all .2s',
        }}
        aria-label="Settings"
      >
        <Settings size={22} />
      </motion.button>

      {/* Avatar name + status */}
      <div
        className="flex flex-col items-center gap-2 mb-6 z-10"
        style={{ animation: 'fadeUp .4s ease both' }}
        >
          <h1
            style={{
              fontFamily: 'var(--font-head)',
              fontWeight: 800,
              color: AI_COLOR,
              fontSize: 'clamp(1.1rem, 4vw, 1.5rem)',
              letterSpacing: '-.02em',
            }}
          >
            Viora AI
          </h1>
        <span
          style={{
            fontSize: 'clamp(.6rem, 1.8vw, .7rem)',
            fontWeight: 600,
            color: 'var(--text-mid)',
            letterSpacing: '.08em',
            textTransform: 'uppercase',
          }}
        >
          Tap avatar to chat
        </span>
      </div>

      {/* Avatar */}
      <div
        className={`mb-10 relative ${showBubble ? 'z-20' : 'z-10'}`}
        onMouseDown={handleMouseDown}
        onMouseUp={handleMouseUp}
        onMouseLeave={handleMouseLeave}
        style={{ animation: 'fadeUp .4s ease both .1s' }}
      >
        <Avatar
          variant="xl"
          animate={true}
          expression={customExpression || voiceStatus}
          className={`cursor-pointer transition-all duration-300 ${isRecording ? 'scale-110' : 'hover:scale-105'}`}
        />

        {/* Vosk Transcription Overlay */}
        <AnimatePresence>
          {isVoskRecording && voskText && (
            <motion.div
              initial={{ opacity: 0, scale: 0.8, y: -10 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.8 }}
              style={{
                position: 'absolute',
                left: 90,
                top: 60,
                width: 200,
                background: 'rgba(30, 16, 48, .92)',
                backdropFilter: 'blur(12px)',
                padding: 12,
                borderRadius: 14,
                border: '1.5px solid rgba(124,58,237,.4)',
                boxShadow: '0 8px 24px rgba(0,0,0,.3)',
                zIndex: 50,
              }}
            >
              <p
                style={{
                  color: '#c084fc',
                  fontSize: '.78rem',
                  lineHeight: 1.6,
                  wordBreak: 'break-word',
                  whiteSpace: 'pre-wrap',
                  maxHeight: 120,
                  overflowY: 'auto',
                }}
              >
                {voskText}
              </p>
              <div
                style={{
                  position: 'absolute',
                  left: -8,
                  top: -2,
                  width: 0,
                  height: 0,
                  borderRight: '10px solid rgba(124,58,237,.4)',
                  borderBottom: '10px solid transparent',
                }}
              />
            </motion.div>
          )}
        </AnimatePresence>

        {/* AI Response Bubble */}
        <AnimatePresence>
          {showBubble && displayVoiceText && (
            <motion.div
              initial={{ opacity: 0, y: 10, scale: 0.95 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="response-bubble"
            >
              <div className="response-bubble-arrow" />
              <p>{displayVoiceText}</p>
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* Main Menu Grid - 5 buttons */}
      <div
        className="grid gap-3 z-10 w-full max-w-[460px] px-4"
        style={{
          gridTemplateColumns: 'repeat(3, 1fr)',
          gridTemplateRows: 'repeat(2, 1fr)',
          animation: 'fadeUp .4s ease both .2s',
        }}
      >
        <MenuButton icon={MessageCircle} label="CHAT" onClick={() => navigate('/chat')} color={AI_COLOR} />
        <MenuButton icon={Camera} label="VISION" onClick={() => navigate('/camera')} color="#38bdf8" />
        <MenuButton icon={Code} label="AGENT" onClick={() => navigate('/tasks')} color="#f7768e" />
        <MenuButton icon={GalleryIcon} label="GALLERY" onClick={() => navigate('/gallery')} color="var(--text-mid)" />
        <MenuButton icon={Cloud} label="WEATHER" onClick={handleWeatherClick} color="#38bdf8" />
        <MenuButton icon={Gamepad2} label="GAMES" onClick={handleGamesClick} color="#f472b6" />
        <MenuButton
          icon={Map}
          label="MAPS"
          onClick={async () => { await fetch('http://localhost:8000/maps/open', { method: 'POST' }); }}
          color="#9ece6a"
        />
        <MenuButton
          icon={Bot}
          label="DEV AI"
          onClick={() => navigate('/devai')}
          color="#f97316"
        />
        <MenuButton
          icon={Shield}
          label="SECURITY"
          onClick={() => { fetchSecurityStatus(); setShowSecurityModal(true); }}
          color="#ef4444"
        />
        <MenuButton
          icon={Terminal}
          label="TERMINAL"
          onClick={() => navigate('/terminal')}
          color="#10b981"
        />
        <MenuButton
          icon={Folder}
          label="FILES"
          onClick={() => navigate('/files')}
          color="#8b5cf6"
        />
        <MenuButton
          icon={CreditCard}
          label="BANKING"
          onClick={handleBankingClick}
          color="#0ea5e9"
        />
      </div>

      {/* Weather Modal */}
      <AnimatePresence>
        {showWeatherModal && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            style={{
              position: 'fixed',
              inset: 0,
              background: 'rgba(0,0,0,0.6)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              zIndex: 100,
              padding: 20,
            }}
            onClick={() => setShowWeatherModal(false)}
          >
            <motion.div
              initial={{ scale: 0.9, y: 20 }}
              animate={{ scale: 1, y: 0 }}
              exit={{ scale: 0.9, y: 20 }}
              style={{
                background: 'var(--surface)',
                borderRadius: 24,
                padding: 24,
                maxWidth: 400,
                width: '100%',
                border: '1.5px solid var(--border)',
                boxShadow: '0 20px 60px rgba(0,0,0,0.3)',
              }}
              onClick={(e) => e.stopPropagation()}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
                <h2 style={{ fontSize: '1.25rem', fontWeight: 700, color: 'var(--text)' }}>Weather</h2>
                <button
                  onClick={() => setShowWeatherModal(false)}
                  style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-mid)', fontSize: '1.5rem' }}
                >
                  ×
                </button>
              </div>

              <form onSubmit={handleSearch} style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
                <input
                  type="text"
                  value={locationInput}
                  onChange={(e) => setLocationInput(e.target.value)}
                  placeholder="Search city..."
                  style={{
                    flex: 1,
                    padding: '12px 16px',
                    borderRadius: 12,
                    border: '1.5px solid var(--border)',
                    background: 'var(--bg)',
                    color: 'var(--text)',
                    fontSize: '1rem',
                    outline: 'none',
                  }}
                />
                <button
                  type="submit"
                  style={{
                    padding: 12,
                    borderRadius: 12,
                    border: 'none',
                    background: AI_COLOR,
                    color: 'white',
                    cursor: 'pointer',
                  }}
                >
                  <Search size={20} />
                </button>
              </form>

              <button
                onClick={handleMyLocation}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: 8,
                  width: '100%',
                  padding: 12,
                  marginBottom: 16,
                  borderRadius: 12,
                  border: '1.5px solid var(--border)',
                  background: 'var(--bg)',
                  color: 'var(--text)',
                  cursor: 'pointer',
                  fontSize: '0.9rem',
                }}
              >
                <MapPin size={18} />
                Use My Location
              </button>

              {weatherLoading && (
                <div style={{ textAlign: 'center', padding: 20, color: 'var(--text-mid)' }}>
                  Loading weather...
                </div>
              )}

              {weatherError && (
                <div style={{ textAlign: 'center', padding: 16, color: '#f7768e', background: 'rgba(247,118,142,0.1)', borderRadius: 12 }}>
                  {weatherError}
                </div>
              )}

              {weatherData && (
                <div style={{ textAlign: 'center', padding: 20, background: 'var(--bg)', borderRadius: 16 }}>
                  <div style={{ fontSize: '3rem', marginBottom: 8 }}>{weatherData.emoji}</div>
                  <div style={{ fontSize: '2rem', fontWeight: 700, color: 'var(--text)' }}>
                    {weatherData.temperature}{weatherData.unit}
                  </div>
                  <div style={{ fontSize: '1.1rem', color: 'var(--text-mid)', marginTop: 4 }}>
                    {weatherData.description}
                  </div>
                  <div style={{ fontSize: '0.9rem', color: AI_COLOR, marginTop: 8, fontWeight: 600 }}>
                    {weatherData.location}
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'center', gap: 16, marginTop: 16, fontSize: '0.85rem', color: 'var(--text-mid)' }}>
                    <span>💧 {weatherData.humidity}%</span>
                    <span>💨 {weatherData.wind_speed} mph</span>
                  </div>
                </div>
              )}
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Games Modal */}
      <AnimatePresence>
        {showGamesModal && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            style={{
              position: 'fixed',
              inset: 0,
              background: 'rgba(0,0,0,0.6)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              zIndex: 100,
              padding: 20,
            }}
            onClick={() => setShowGamesModal(false)}
          >
            <motion.div
              initial={{ scale: 0.9, y: 20 }}
              animate={{ scale: 1, y: 0 }}
              exit={{ scale: 0.9, y: 20 }}
              style={{
                background: 'var(--surface)',
                borderRadius: 24,
                padding: 24,
                maxWidth: 500,
                width: '100%',
                maxHeight: '80vh',
                border: '1.5px solid var(--border)',
                boxShadow: '0 20px 60px rgba(0,0,0,0.3)',
                overflow: 'hidden',
                display: 'flex',
                flexDirection: 'column',
              }}
              onClick={(e) => e.stopPropagation()}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
                <h2 style={{ fontSize: '1.25rem', fontWeight: 700, color: 'var(--text)' }}>Games</h2>
                <button
                  onClick={() => setShowGamesModal(false)}
                  style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-mid)', fontSize: '1.5rem' }}
                >
                  ×
                </button>
              </div>

              {gamesLoading && (
                <div style={{ textAlign: 'center', padding: 40, color: 'var(--text-mid)' }}>
                  Loading games...
                </div>
              )}

              {!gamesLoading && gamesList.length === 0 && (
                <div style={{ textAlign: 'center', padding: 40, color: 'var(--text-mid)' }}>
                  No games found. Add games to /opt or /usr/games
                </div>
              )}

              <div style={{ 
                display: 'grid', 
                gridTemplateColumns: 'repeat(auto-fill, minmax(100px, 1fr))', 
                gap: 12,
                overflowY: 'auto',
                paddingBottom: 16,
              }}>
                {gamesList.map((game) => (
                  <motion.button
                    key={game.id}
                    whileHover={{ scale: 1.05 }}
                    whileTap={{ scale: 0.95 }}
                    onClick={() => launchGame(game)}
                    style={{
                      display: 'flex',
                      flexDirection: 'column',
                      alignItems: 'center',
                      justifyContent: 'center',
                      gap: 8,
                      padding: 12,
                      borderRadius: 16,
                      border: '1.5px solid var(--border)',
                      background: 'var(--bg)',
                      cursor: 'pointer',
                      minHeight: 90,
                    }}
                  >
                    <span style={{ fontSize: '2rem' }}>{game.icon}</span>
                    <span style={{ fontSize: '0.7rem', color: 'var(--text)', fontWeight: 500, textAlign: 'center', lineHeight: 1.2 }}>
                      {game.name}
                    </span>
                  </motion.button>
                ))}
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Security Modal */}
      <AnimatePresence>
        {showSecurityModal && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            style={{
              position: 'fixed',
              inset: 0,
              background: 'rgba(0,0,0,0.6)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              zIndex: 100,
              padding: 20,
            }}
            onClick={() => setShowSecurityModal(false)}
          >
            <motion.div
              initial={{ scale: 0.9, y: 20 }}
              animate={{ scale: 1, y: 0 }}
              exit={{ scale: 0.9, y: 20 }}
              style={{
                background: 'var(--surface)',
                borderRadius: 24,
                padding: 24,
                maxWidth: 360,
                width: '100%',
                border: '1.5px solid var(--border)',
                boxShadow: '0 20px 60px rgba(0,0,0,0.3)',
              }}
              onClick={(e) => e.stopPropagation()}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
                <h2 style={{ fontSize: '1.25rem', fontWeight: 700, color: 'var(--text)' }}>Security</h2>
                <button
                  onClick={() => setShowSecurityModal(false)}
                  style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-mid)', fontSize: '1.5rem' }}
                >
                  ×
                </button>
              </div>

              {/* Security Status */}
              <div style={{ 
                display: 'flex', 
                alignItems: 'center', 
                justifyContent: 'center',
                gap: 12,
                padding: 20,
                borderRadius: 16,
                marginBottom: 20,
                background: securityStatus === 'armed' ? 'rgba(239,68,68,0.1)' : 
                           securityStatus === 'alarm' ? 'rgba(239,68,68,0.2)' : 'rgba(34,197,94,0.1)',
                border: `1.5px solid ${securityStatus === 'armed' ? 'rgba(239,68,68,0.3)' : 
                                   securityStatus === 'alarm' ? 'rgba(239,68,68,0.5)' : 'rgba(34,197,94,0.3)'}`,
              }}>
                {securityStatus === 'disarmed' && <Unlock size={32} style={{ color: '#22c55e' }} />}
                {securityStatus === 'armed' && <Lock size={32} style={{ color: '#ef4444' }} />}
                {securityStatus === 'alarm' && <Siren size={32} style={{ color: '#ef4444' }} className="animate-pulse" />}
                <span style={{ 
                  fontSize: '1.1rem', 
                  fontWeight: 600, 
                  color: securityStatus === 'disarmed' ? '#22c55e' : '#ef4444',
                  textTransform: 'capitalize',
                }}>
                  {securityStatus}
                </span>
              </div>

              {/* Action Buttons */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                {securityStatus === 'alarm' && (
                  <form onSubmit={defuseAlarm}>
                    <input
                      type="password"
                      value={defusePassword}
                      onChange={(e) => setDefusePassword(e.target.value)}
                      placeholder="Enter password to defuse..."
                      style={{
                        width: '100%',
                        padding: '12px 16px',
                        borderRadius: 12,
                        border: defuseError ? '1.5px solid #ef4444' : '1.5px solid var(--border)',
                        background: 'var(--bg)',
                        color: 'var(--text)',
                        fontSize: '1rem',
                        outline: 'none',
                        marginBottom: 12,
                      }}
                    />
                    {defuseError && (
                      <p style={{ color: '#ef4444', fontSize: '0.85rem', marginBottom: 12 }}>{defuseError}</p>
                    )}
                    <button
                      type="submit"
                      style={{
                        width: '100%',
                        padding: 14,
                        borderRadius: 12,
                        border: 'none',
                        background: '#22c55e',
                        color: 'white',
                        fontSize: '1rem',
                        fontWeight: 600,
                        cursor: 'pointer',
                      }}
                    >
                      Defuse Alarm
                    </button>
                  </form>
                )}

                {securityStatus !== 'alarm' && (
                  <button
                    onClick={triggerAlarm}
                    disabled={securityLoading}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      gap: 8,
                      padding: 14,
                      borderRadius: 12,
                      border: 'none',
                      background: '#ef4444',
                      color: 'white',
                      fontSize: '1rem',
                      fontWeight: 600,
                      cursor: securityLoading ? 'not-allowed' : 'pointer',
                      opacity: securityLoading ? 0.6 : 1,
                    }}
                  >
                    <Siren size={20} />
                    Trigger Alarm
                  </button>
                )}

                <button
                  onClick={() => setShowSecurityModal(false)}
                  style={{
                    padding: 14,
                    borderRadius: 12,
                    border: '1.5px solid var(--border)',
                    background: 'transparent',
                    color: 'var(--text)',
                    fontSize: '1rem',
                    fontWeight: 500,
                    cursor: 'pointer',
                  }}
                >
                  Close
                </button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Banking Modal */}
      <AnimatePresence>
        {showBankingModal && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            style={{
              position: 'fixed',
              inset: 0,
              background: 'rgba(0,0,0,0.6)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              zIndex: 100,
              padding: 20,
            }}
            onClick={() => setShowBankingModal(false)}
          >
            <motion.div
              initial={{ scale: 0.9, y: 20 }}
              animate={{ scale: 1, y: 0 }}
              exit={{ scale: 0.9, y: 20 }}
              style={{
                background: 'linear-gradient(180deg, #1a365d 0%, #0f172a 100%)',
                borderRadius: 24,
                padding: 24,
                maxWidth: 440,
                width: '100%',
                maxHeight: '90vh',
                border: '1.5px solid #2d4a6f',
                boxShadow: '0 20px 60px rgba(0,0,0,0.5)',
                overflow: 'hidden',
                display: 'flex',
                flexDirection: 'column',
              }}
              onClick={(e) => e.stopPropagation()}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <CreditCard size={24} color="#60a5fa" />
                  <h2 style={{ fontSize: '1.25rem', fontWeight: 700, color: '#e2e8f0' }}>My Bank</h2>
                </div>
                <button
                  onClick={() => setShowBankingModal(false)}
                  style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#94a3b8', fontSize: '1.5rem' }}
                >
                  ×
                </button>
              </div>

              {/* Tabs */}
              <div style={{ display: 'flex', gap: 8, marginBottom: 16, overflowX: 'auto', paddingBottom: 8 }}>
                {['accounts', 'transactions', 'owing', 'owed', 'bills', 'savings'].map(tab => (
                  <button
                    key={tab}
                    onClick={() => setActiveTab(tab)}
                    style={{
                      padding: '8px 16px',
                      borderRadius: 20,
                      border: 'none',
                      background: activeTab === tab ? '#2563eb' : 'rgba(255,255,255,0.1)',
                      color: activeTab === tab ? '#fff' : '#94a3b8',
                      fontSize: '0.8rem',
                      fontWeight: 600,
                      cursor: 'pointer',
                      whiteSpace: 'nowrap',
                    }}
                  >
                    {tab === 'accounts' ? 'Accounts' : tab === 'transactions' ? 'Transactions' : tab === 'owing' ? 'Owing' : tab === 'owed' ? 'Owed to Me' : tab === 'bills' ? 'Bills' : 'Savings'}
                  </button>
                ))}
              </div>

              {bankLoading && (
                <div style={{ textAlign: 'center', padding: 40, color: '#94a3b8' }}>
                  Loading...
                </div>
              )}

              {!bankLoading && bankAccounts && (
                <div style={{ flex: 1, overflowY: 'auto' }}>
                  {/* ACCOUNTS TAB */}
                  {activeTab === 'accounts' && (
                    <>
                      {(() => {
                        const totalAccounts = bankAccounts.accounts.reduce((sum, a) => sum + a.balance, 0);
                        const totalOwedToMe = (bankAccounts.owed_to_me || []).reduce((s, o) => s + o.amount, 0);
                        const totalOwing = (bankAccounts.owing || []).reduce((s, o) => s + o.amount, 0);
                        const totalSavings = (bankAccounts.savings_goals || []).reduce((s, g) => s + g.current, 0);
                        const grandTotal = totalAccounts + totalOwedToMe - totalOwing + totalSavings;
                        return (
                          <div style={{
                            background: 'linear-gradient(135deg, #7c3aed 0%, #5b21b6 100%)',
                            borderRadius: 20,
                            padding: 20,
                            marginBottom: 16,
                            boxShadow: '0 8px 24px rgba(124, 58, 237, 0.4)',
                          }}>
                            <div style={{ fontSize: '0.85rem', color: '#ddd6fe', marginBottom: 4 }}>Grand Total</div>
                            <div style={{ fontSize: '2.5rem', fontWeight: 700, color: '#fff' }}>
                              ${grandTotal.toFixed(2)}
                            </div>
                            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', marginTop: 12, paddingTop: 12, borderTop: '1px solid rgba(255,255,255,0.2)', gap: 8 }}>
                              <div><div style={{ fontSize: '0.6rem', color: '#c4b5fd' }}>Accounts</div><div style={{ fontSize: '0.8rem', fontWeight: 600, color: '#fff' }}>${totalAccounts.toFixed(2)}</div></div>
                              <div><div style={{ fontSize: '0.6rem', color: '#c4b5fd' }}>Owed to Me</div><div style={{ fontSize: '0.8rem', fontWeight: 600, color: '#86efac' }}>+${totalOwedToMe.toFixed(2)}</div></div>
                              <div><div style={{ fontSize: '0.6rem', color: '#c4b5fd' }}>I Owe</div><div style={{ fontSize: '0.8rem', fontWeight: 600, color: '#fca5a5' }}>-${totalOwing.toFixed(2)}</div></div>
                              <div><div style={{ fontSize: '0.6rem', color: '#c4b5fd' }}>Savings</div><div style={{ fontSize: '0.8rem', fontWeight: 600, color: '#fcd34d' }}>+${totalSavings.toFixed(2)}</div></div>
                            </div>
                          </div>
                        );
                      })()}
                      <div style={{
                        background: 'linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%)',
                        borderRadius: 20,
                        padding: 20,
                        marginBottom: 16,
                        boxShadow: '0 8px 24px rgba(37, 99, 235, 0.4)',
                      }}>
                        <div style={{ fontSize: '0.85rem', color: '#bfdbfe', marginBottom: 8 }}>Bank Balance</div>
                        <div style={{ fontSize: '2rem', fontWeight: 700, color: '#fff' }}>
                          ${(bankAccounts.accounts.reduce((sum, a) => sum + a.balance, 0)).toFixed(2)}
                        </div>
                        <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 12, paddingTop: 12, borderTop: '1px solid rgba(255,255,255,0.2)' }}>
                          <div><div style={{ fontSize: '0.7rem', color: '#93c5fd' }}>Income</div><div style={{ fontSize: '0.9rem', fontWeight: 600, color: '#86efac' }}>+${(bankAccounts.transactions.filter(t => t.amount > 0).reduce((s, t) => s + t.amount, 0)).toFixed(2)}</div></div>
                          <div><div style={{ fontSize: '0.7rem', color: '#93c5fd' }}>Expenses</div><div style={{ fontSize: '0.9rem', fontWeight: 600, color: '#fca5a5' }}>-${Math.abs(bankAccounts.transactions.filter(t => t.amount < 0).reduce((s, t) => s + t.amount, 0)).toFixed(2)}</div></div>
                          <div><div style={{ fontSize: '0.7rem', color: '#93c5fd' }}>Net</div><div style={{ fontSize: '0.9rem', fontWeight: 600, color: bankAccounts.transactions.reduce((s, t) => s + t.amount, 0) >= 0 ? '#86efac' : '#fca5a5' }}>${bankAccounts.transactions.reduce((s, t) => s + t.amount, 0).toFixed(2)}</div></div>
                        </div>
                      </div>
                      {bankAccounts.accounts.map(account => (
                        <div key={account.id} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: 14, marginBottom: 8, borderRadius: 12, background: 'rgba(255,255,255,0.05)', border: '1px solid #334155' }}>
                          <div><div style={{ fontWeight: 600, color: '#e2e8f0' }}>{account.name}</div><div style={{ fontSize: '0.75rem', color: '#64748b' }}>{account.account_number}</div></div>
                          <div style={{ fontSize: '1.1rem', fontWeight: 700, color: account.balance >= 0 ? '#22c55e' : '#ef4444' }}>${account.balance.toFixed(2)}</div>
                        </div>
                      ))}
                    </>
                  )}

                  {/* TRANSACTIONS TAB */}
                  {activeTab === 'transactions' && (
                    <>
                      {bankAccounts.transactions.slice(0, 15).map(tx => (
                        <div key={tx.id} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '10px 0', borderBottom: '1px solid #334155' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                            <div style={{ width: 32, height: 32, borderRadius: 8, background: tx.amount > 0 ? 'rgba(34,197,94,0.2)' : 'rgba(239,68,68,0.2)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: tx.amount > 0 ? '#22c55e' : '#ef4444' }}>{tx.amount > 0 ? '↑' : '↓'}</div>
                            <div><div style={{ fontWeight: 500, color: '#e2e8f0', fontSize: '0.85rem' }}>{tx.description}</div><div style={{ fontSize: '0.7rem', color: '#64748b' }}>{tx.date} • {tx.category}</div></div>
                          </div>
                          <div style={{ fontWeight: 600, color: tx.amount > 0 ? '#22c55e' : '#ef4444' }}>{tx.amount > 0 ? '+' : ''}{tx.amount.toFixed(2)}</div>
                        </div>
                      ))}
                      <form onSubmit={addTransaction} style={{ marginTop: 16, paddingTop: 16, borderTop: '1px solid #334155' }}>
                        <div style={{ fontSize: '0.85rem', fontWeight: 600, marginBottom: 10, color: '#94a3b8' }}>Add Transaction</div>
                        <div style={{ display: 'flex', gap: 6, marginBottom: 8 }}>
                          <select value={newTransaction.type} onChange={(e) => setNewTransaction({ ...newTransaction, type: e.target.value })} style={{ padding: '10px 12px', borderRadius: 10, border: '1px solid #334155', background: 'rgba(255,255,255,0.05)', color: '#e2e8f0', fontSize: '0.85rem' }}>
                            <option value="credit">Credit (+)</option>
                            <option value="debit">Debit (-)</option>
                          </select>
                          <input type="number" step="0.01" value={newTransaction.amount} onChange={(e) => setNewTransaction({ ...newTransaction, amount: e.target.value })} placeholder="Amount" style={{ flex: 1, padding: '10px 12px', borderRadius: 10, border: '1px solid #334155', background: 'rgba(255,255,255,0.05)', color: '#e2e8f0', fontSize: '0.85rem' }} />
                        </div>
                        <div style={{ display: 'flex', gap: 6, marginBottom: 8 }}>
                          <input type="text" value={newTransaction.description} onChange={(e) => setNewTransaction({ ...newTransaction, description: e.target.value })} placeholder="Description" style={{ flex: 1, padding: '10px 12px', borderRadius: 10, border: '1px solid #334155', background: 'rgba(255,255,255,0.05)', color: '#e2e8f0', fontSize: '0.85rem' }} />
                          <select value={newTransaction.category} onChange={(e) => setNewTransaction({ ...newTransaction, category: e.target.value })} style={{ padding: '10px 12px', borderRadius: 10, border: '1px solid #334155', background: 'rgba(255,255,255,0.05)', color: '#e2e8f0', fontSize: '0.85rem' }}>
                            <option>Food</option><option>Transport</option><option>Bills</option><option>Entertainment</option><option>Shopping</option><option>Health</option><option>Income</option><option>Transfer</option><option>Other</option>
                          </select>
                        </div>
                        <button type="submit" style={{ width: '100%', padding: 12, borderRadius: 10, border: 'none', background: '#2563eb', color: 'white', fontSize: '0.9rem', fontWeight: 600, cursor: 'pointer' }}>Add Transaction</button>
                      </form>
                    </>
                  )}

                  {/* OWING TAB */}
                  {activeTab === 'owing' && (
                    <>
                      {bankAccounts.owing && bankAccounts.owing.length > 0 && (
                        <div style={{ padding: 16, borderRadius: 14, background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)', marginBottom: 16 }}>
                          <div style={{ fontSize: '0.8rem', color: '#fca5a5' }}>Total Owed</div>
                          <div style={{ fontSize: '1.5rem', fontWeight: 700, color: '#ef4444' }}>${bankAccounts.owing.reduce((s, o) => s + o.amount, 0).toFixed(2)}</div>
                        </div>
                      )}
                      {bankAccounts.owing.map(o => (
                        <div key={o.id} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '12px 0', borderBottom: '1px solid #334155' }}>
                          <div><div style={{ fontWeight: 500, color: '#e2e8f0' }}>{o.person}</div><div style={{ fontSize: '0.7rem', color: '#64748b' }}>{o.reason} • {o.date}</div></div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}><div style={{ fontWeight: 600, color: '#ef4444' }}>${o.amount.toFixed(2)}</div><button onClick={() => deleteOwing(o.id)} style={{ background: 'none', border: 'none', color: '#fca5a5', cursor: 'pointer' }}>×</button></div>
                        </div>
                      ))}
                      <form onSubmit={addOwing} style={{ marginTop: 16, paddingTop: 16, borderTop: '1px solid #334155' }}>
                        <div style={{ fontSize: '0.85rem', fontWeight: 600, marginBottom: 10, color: '#94a3b8' }}>Add Money Owed</div>
                        <div style={{ display: 'flex', gap: 6, marginBottom: 8 }}><input type="text" value={newOwing.person} onChange={(e) => setNewOwing({ ...newOwing, person: e.target.value })} placeholder="Person" style={{ flex: 1, padding: '10px 12px', borderRadius: 10, border: '1px solid #334155', background: 'rgba(255,255,255,0.05)', color: '#e2e8f0', fontSize: '0.85rem' }} /><input type="number" step="0.01" value={newOwing.amount} onChange={(e) => setNewOwing({ ...newOwing, amount: e.target.value })} placeholder="Amount" style={{ width: 100, padding: '10px 12px', borderRadius: 10, border: '1px solid #334155', background: 'rgba(255,255,255,0.05)', color: '#e2e8f0', fontSize: '0.85rem' }} /></div>
                        <input type="text" value={newOwing.reason} onChange={(e) => setNewOwing({ ...newOwing, reason: e.target.value })} placeholder="Reason" style={{ width: '100%', padding: '10px 12px', borderRadius: 10, border: '1px solid #334155', background: 'rgba(255,255,255,0.05)', color: '#e2e8f0', fontSize: '0.85rem', marginBottom: 10 }} />
                        <button type="submit" style={{ width: '100%', padding: 12, borderRadius: 10, border: 'none', background: '#dc2626', color: 'white', fontSize: '0.9rem', fontWeight: 600, cursor: 'pointer' }}>Add Owed Money</button>
                      </form>
                    </>
                  )}

                  {/* OWED TO ME TAB */}
                  {activeTab === 'owed' && (
                    <>
                      {bankAccounts.owed_to_me && bankAccounts.owed_to_me.length > 0 && (
                        <div style={{ padding: 16, borderRadius: 14, background: 'rgba(34,197,94,0.1)', border: '1px solid rgba(34,197,94,0.3)', marginBottom: 16 }}>
                          <div style={{ fontSize: '0.8rem', color: '#86efac' }}>Total Owed to You</div>
                          <div style={{ fontSize: '1.5rem', fontWeight: 700, color: '#22c55e' }}>${bankAccounts.owed_to_me.reduce((s, o) => s + o.amount, 0).toFixed(2)}</div>
                        </div>
                      )}
                      {bankAccounts.owed_to_me && bankAccounts.owed_to_me.length > 0 ? bankAccounts.owed_to_me.map(o => (
                        <div key={o.id} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '12px 0', borderBottom: '1px solid #334155' }}>
                          <div><div style={{ fontWeight: 500, color: '#e2e8f0' }}>{o.person}</div><div style={{ fontSize: '0.7rem', color: '#64748b' }}>{o.reason} • {o.date}</div></div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}><div style={{ fontWeight: 600, color: '#22c55e' }}>${o.amount.toFixed(2)}</div><button onClick={() => deleteOwedToMe(o.id)} style={{ background: 'none', border: 'none', color: '#86efac', cursor: 'pointer' }}>×</button></div>
                        </div>
                      )) : <div style={{ textAlign: 'center', color: '#64748b', padding: 20 }}>No one owes you money</div>}
                      <form onSubmit={addOwedToMe} style={{ marginTop: 16, paddingTop: 16, borderTop: '1px solid #334155' }}>
                        <div style={{ fontSize: '0.85rem', fontWeight: 600, marginBottom: 10, color: '#94a3b8' }}>Add Money Owed to You</div>
                        <div style={{ display: 'flex', gap: 6, marginBottom: 8 }}><input type="text" value={newOwedToMe.person} onChange={(e) => setNewOwedToMe({ ...newOwedToMe, person: e.target.value })} placeholder="Person" style={{ flex: 1, padding: '10px 12px', borderRadius: 10, border: '1px solid #334155', background: 'rgba(255,255,255,0.05)', color: '#e2e8f0', fontSize: '0.85rem' }} /><input type="number" step="0.01" value={newOwedToMe.amount} onChange={(e) => setNewOwedToMe({ ...newOwedToMe, amount: e.target.value })} placeholder="Amount" style={{ width: 100, padding: '10px 12px', borderRadius: 10, border: '1px solid #334155', background: 'rgba(255,255,255,0.05)', color: '#e2e8f0', fontSize: '0.85rem' }} /></div>
                        <input type="text" value={newOwedToMe.reason} onChange={(e) => setNewOwedToMe({ ...newOwedToMe, reason: e.target.value })} placeholder="Reason" style={{ width: '100%', padding: '10px 12px', borderRadius: 10, border: '1px solid #334155', background: 'rgba(255,255,255,0.05)', color: '#e2e8f0', fontSize: '0.85rem', marginBottom: 10 }} />
                        <button type="submit" style={{ width: '100%', padding: 12, borderRadius: 10, border: 'none', background: '#22c55e', color: 'white', fontSize: '0.9rem', fontWeight: 600, cursor: 'pointer' }}>Add Owed to Me</button>
                      </form>
                    </>
                  )}

                  {/* BILLS TAB */}
                  {activeTab === 'bills' && (
                    <>
                      {bankAccounts.bills && (
                        <>
                          <div style={{ padding: 16, borderRadius: 14, background: 'rgba(251,191,36,0.1)', border: '1px solid rgba(251,191,36,0.3)', marginBottom: 16 }}>
                            <div style={{ fontSize: '0.8rem', color: '#fde047' }}>Upcoming Bills</div>
                            <div style={{ fontSize: '1.5rem', fontWeight: 700, color: '#fbbf24' }}>${bankAccounts.bills.filter(b => !b.paid).reduce((s, b) => s + b.amount, 0).toFixed(2)}</div>
                          </div>
                          {bankAccounts.bills.map(bill => (
                            <div key={bill.id} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '12px 0', borderBottom: '1px solid #334155' }}>
                              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                                <button onClick={() => toggleBillPaid(bill.id)} style={{ width: 24, height: 24, borderRadius: 6, border: bill.paid ? 'none' : '2px solid #64748b', background: bill.paid ? '#22c55e' : 'transparent', color: bill.paid ? '#fff' : 'transparent', fontSize: '0.8rem', cursor: 'pointer' }}>{bill.paid ? '✓' : ''}</button>
                                <div><div style={{ fontWeight: 500, color: bill.paid ? '#64748b' : '#e2e8f0', textDecoration: bill.paid ? 'line-through' : 'none' }}>{bill.name}</div><div style={{ fontSize: '0.7rem', color: '#64748b' }}>Due: {bill.due_date} • {bill.category}</div></div>
                              </div>
                              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}><div style={{ fontWeight: 600, color: bill.paid ? '#64748b' : '#fbbf24' }}>${bill.amount.toFixed(2)}</div><button onClick={() => deleteBill(bill.id)} style={{ background: 'none', border: 'none', color: '#64748b', cursor: 'pointer' }}>×</button></div>
                            </div>
                          ))}
                        </>
                      )}
                      <form onSubmit={addBill} style={{ marginTop: 16, paddingTop: 16, borderTop: '1px solid #334155' }}>
                        <div style={{ fontSize: '0.85rem', fontWeight: 600, marginBottom: 10, color: '#94a3b8' }}>Add Bill</div>
                        <div style={{ display: 'flex', gap: 6, marginBottom: 8 }}><input type="text" value={newBill.name} onChange={(e) => setNewBill({ ...newBill, name: e.target.value })} placeholder="Bill name" style={{ flex: 1, padding: '10px 12px', borderRadius: 10, border: '1px solid #334155', background: 'rgba(255,255,255,0.05)', color: '#e2e8f0', fontSize: '0.85rem' }} /><input type="number" step="0.01" value={newBill.amount} onChange={(e) => setNewBill({ ...newBill, amount: e.target.value })} placeholder="Amount" style={{ width: 90, padding: '10px 12px', borderRadius: 10, border: '1px solid #334155', background: 'rgba(255,255,255,0.05)', color: '#e2e8f0', fontSize: '0.85rem' }} /></div>
                        <div style={{ display: 'flex', gap: 6, marginBottom: 8 }}><input type="date" value={newBill.due_date} onChange={(e) => setNewBill({ ...newBill, due_date: e.target.value })} style={{ flex: 1, padding: '10px 12px', borderRadius: 10, border: '1px solid #334155', background: 'rgba(255,255,255,0.05)', color: '#e2e8f0', fontSize: '0.85rem' }} /><select value={newBill.category} onChange={(e) => setNewBill({ ...newBill, category: e.target.value })} style={{ padding: '10px 12px', borderRadius: 10, border: '1px solid #334155', background: 'rgba(255,255,255,0.05)', color: '#e2e8f0', fontSize: '0.85rem' }}><option>Utilities</option><option>Services</option><option>Housing</option><option>Insurance</option><option>Other</option></select></div>
                        <button type="submit" style={{ width: '100%', padding: 12, borderRadius: 10, border: 'none', background: '#fbbf24', color: '#000', fontSize: '0.9rem', fontWeight: 600, cursor: 'pointer' }}>Add Bill</button>
                      </form>
                    </>
                  )}

                  {/* SAVINGS TAB */}
                  {activeTab === 'savings' && (
                    <>
                      {bankAccounts.savings_goals && (
                        <>
                          <div style={{ padding: 16, borderRadius: 14, background: 'rgba(139,92,246,0.1)', border: '1px solid rgba(139,92,246,0.3)', marginBottom: 16 }}>
                            <div style={{ fontSize: '0.8rem', color: '#c4b5fd' }}>Total Saved</div>
                            <div style={{ fontSize: '1.5rem', fontWeight: 700, color: '#a78bfa' }}>${bankAccounts.savings_goals.reduce((s, g) => s + g.current, 0).toFixed(2)}</div>
                          </div>
                          {bankAccounts.savings_goals.map(goal => (
                            <div key={goal.id} style={{ padding: '12px 0', borderBottom: '1px solid #334155' }}>
                              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}><span style={{ fontSize: '1.2rem' }}>{goal.icon}</span><span style={{ fontWeight: 500, color: '#e2e8f0' }}>{goal.name}</span></div>
                                <button onClick={() => deleteSavingsGoal(goal.id)} style={{ background: 'none', border: 'none', color: '#64748b', cursor: 'pointer' }}>×</button>
                              </div>
                              <div style={{ background: '#1e293b', borderRadius: 8, height: 8, overflow: 'hidden', marginBottom: 6 }}><div style={{ width: `${(goal.current / goal.target) * 100}%`, background: 'linear-gradient(90deg, #8b5cf6, #a78bfa)', height: '100%', borderRadius: 8 }} /></div>
                              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem', color: '#64748b' }}><span>${goal.current.toFixed(2)}</span><span>${goal.target.toFixed(2)}</span></div>
                              <button onClick={() => { const amt = prompt('Amount to add:'); if (amt) addToSavingsGoal(goal.id, amt); }} style={{ marginTop: 8, width: '100%', padding: 8, borderRadius: 8, border: '1px solid #8b5cf6', background: 'transparent', color: '#a78bfa', fontSize: '0.8rem', cursor: 'pointer' }}>Add Money</button>
                            </div>
                          ))}
                        </>
                      )}
                      <form onSubmit={addSavingsGoal} style={{ marginTop: 16, paddingTop: 16, borderTop: '1px solid #334155' }}>
                        <div style={{ fontSize: '0.85rem', fontWeight: 600, marginBottom: 10, color: '#94a3b8' }}>Add Savings Goal</div>
                        <div style={{ display: 'flex', gap: 6, marginBottom: 8 }}><input type="text" value={newSavingsGoal.name} onChange={(e) => setNewSavingsGoal({ ...newSavingsGoal, name: e.target.value })} placeholder="Goal name" style={{ flex: 1, padding: '10px 12px', borderRadius: 10, border: '1px solid #334155', background: 'rgba(255,255,255,0.05)', color: '#e2e8f0', fontSize: '0.85rem' }} /><input type="number" step="0.01" value={newSavingsGoal.target} onChange={(e) => setNewSavingsGoal({ ...newSavingsGoal, target: e.target.value })} placeholder="Target" style={{ width: 100, padding: '10px 12px', borderRadius: 10, border: '1px solid #334155', background: 'rgba(255,255,255,0.05)', color: '#e2e8f0', fontSize: '0.85rem' }} /></div>
                        <select value={newSavingsGoal.icon} onChange={(e) => setNewSavingsGoal({ ...newSavingsGoal, icon: e.target.value })} style={{ width: '100%', padding: '10px 12px', borderRadius: 10, border: '1px solid #334155', background: 'rgba(255,255,255,0.05)', color: '#e2e8f0', fontSize: '0.85rem', marginBottom: 10 }}>
                          <option>💰</option><option>🏠</option><option>✈️</option><option>🚗</option><option>📱</option><option>💻</option><option>🎮</option><option>🎓</option><option>🛡️</option><option>💍</option>
                        </select>
                        <button type="submit" style={{ width: '100%', padding: 12, borderRadius: 10, border: 'none', background: '#8b5cf6', color: 'white', fontSize: '0.9rem', fontWeight: 600, cursor: 'pointer' }}>Add Goal</button>
                      </form>
                    </>
                  )}
                </div>
              )}
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
