// src/App.jsx

import React, { useState, useRef } from 'react';
import { ChevronDownIcon, BellIcon, XMarkIcon } from '@heroicons/react/24/solid';

// Mock Ledger event data (kept for initial display)
const mockEvents = [
  { event_id: 'NUM-001-4-A1B2', rule_id: 'NUM-001', severity: 'WARN', note: 'Budget increased from baseline.', created_at: '2025-09-30 10:30:15' },
  { event_id: 'DATE-001-7-C3D4', rule_id: 'DATE-001A', severity: 'INFO', note: 'Deadline is within the acceptable range.', created_at: '2025-09-30 10:29:55' },
  { event_id: 'NUM-001-3-E5F6', rule_id: 'NUM-001', severity: 'INFO', note: 'Initial budget set.', created_at: '2025-09-29 18:05:10' },
  { event_id: 'SYS-INIT-1-G7H8', rule_id: 'SYS-INIT', severity: 'INFO', note: 'Session demo-001 initialized.', created_at: '2025-09-29 18:00:00' },
];

// Severity color configuration
const severityConfig = {
  info: {
    badge: 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300',
    icon: 'ℹ️',
  },
  warn: {
    badge: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-300',
    icon: '⚠️',
  },
  error: {
    badge: 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300',
    icon: '❌',
  },
};

const API_BASE_URL = 'http://localhost:5001';
const API_TOKEN = '39b14f807ea38a7b391af544d7eaf9cc188b83c89d20b7280fb48357249ea4b2';

export default function App() {
  const [message, setMessage] = useState('');
  const [events, setEvents] = useState(mockEvents);
  const [banners, setBanners] = useState([]);
  const [sessionId] = useState('demo-session');
  const turnIdRef = useRef(1);
  const [demoRunning, setDemoRunning] = useState(false);

  // Banner management with auto-dismiss
  const addBanner = (message, type = 'warning') => {
    const newBanner = { id: Date.now(), message, type };
    setBanners(prev => [...prev, newBanner]);
    
    setTimeout(() => {
      setBanners(prev => prev.filter(b => b.id !== newBanner.id));
    }, 5000);
  };

  const dismissBanner = (id) => {
    setBanners(prev => prev.filter(b => b.id !== id));
  };

  // Send message to backend
  const sendMessage = async (messageText) => {
    try {
      const response = await fetch(`${API_BASE_URL}/process`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${API_TOKEN}`,
        },
        body: JSON.stringify({
          session_id: sessionId,
          turn_id: turnIdRef.current,
          message_text: messageText,
        }),
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      turnIdRef.current += 1;

      return data;
    } catch (error) {
      console.error('Error sending message:', error);
      addBanner(`Error: ${error.message}`, 'error');
      throw error;
    }
  };

  // Handle manual message sending
  const handleSendMessage = async () => {
    if (!message.trim()) return;

    try {
      const data = await sendMessage(message);
      
      if (data.events && data.events.length > 0) {
        // Add events to the top of the list
        setEvents(prev => [...data.events.map(e => ({
          event_id: e.event_id,
          rule_id: e.rule_id,
          severity: e.severity,
          note: e.note,
          created_at: new Date(e.created_at).toLocaleString(),
        })), ...prev]);

        // Check for warnings
        const hasWarning = data.events.some(e => e.severity === 'warn');
        if (hasWarning) {
          const warningEvent = data.events.find(e => e.severity === 'warn');
          addBanner(warningEvent.note, 'warning');
        }
      }

      setMessage('');
    } catch (error) {
      // Error already handled in sendMessage
    }
  };

  // Demo: Budget Drift
  const runBudgetDemo = async () => {
    if (demoRunning) return;
    setDemoRunning(true);

    try {
      // Step 1: Set baseline
      const baseline = await sendMessage('Budget is $500000');
      if (baseline.events) {
        setEvents(prev => [...baseline.events.map(e => ({
          event_id: e.event_id,
          rule_id: e.rule_id,
          severity: e.severity,
          note: e.note,
          created_at: new Date(e.created_at).toLocaleString(),
        })), ...prev]);
      }

      // Wait 1 second
      await new Promise(r => setTimeout(r, 1000));

      // Step 2: Trigger drift
      const drift = await sendMessage('Update budget to $550000');
      if (drift.events) {
        setEvents(prev => [...drift.events.map(e => ({
          event_id: e.event_id,
          rule_id: e.rule_id,
          severity: e.severity,
          note: e.note,
          created_at: new Date(e.created_at).toLocaleString(),
        })), ...prev]);

        const hasWarning = drift.events.some(e => e.severity === 'warn');
        if (hasWarning) {
          addBanner('Budget drift detected: $500000 → $550000', 'warning');
        }
      }

      addBanner('Budget demo completed', 'success');
    } catch (error) {
      // Error already handled
    } finally {
      setDemoRunning(false);
    }
  };

  // Demo: Deadline Drift
  const runDeadlineDemo = async () => {
    if (demoRunning) return;
    setDemoRunning(true);

    try {
      // Step 1: Set baseline
      const baseline = await sendMessage('Deadline is 2025-11-15');
      if (baseline.events) {
        setEvents(prev => [...baseline.events.map(e => ({
          event_id: e.event_id,
          rule_id: e.rule_id,
          severity: e.severity,
          note: e.note,
          created_at: new Date(e.created_at).toLocaleString(),
        })), ...prev]);
      }

      await new Promise(r => setTimeout(r, 1000));

      // Step 2: Trigger drift
      const drift = await sendMessage('Deadline moved to 2025-11-30');
      if (drift.events) {
        setEvents(prev => [...drift.events.map(e => ({
          event_id: e.event_id,
          rule_id: e.rule_id,
          severity: e.severity,
          note: e.note,
          created_at: new Date(e.created_at).toLocaleString(),
        })), ...prev]);

        const hasWarning = drift.events.some(e => e.severity === 'warn');
        if (hasWarning) {
          addBanner('Deadline drift detected: 2025-11-15 → 2025-11-30', 'warning');
        }
      }

      addBanner('Deadline demo completed', 'success');
    } catch (error) {
      // Error already handled
    } finally {
      setDemoRunning(false);
    }
  };

  // Demo: Status Drift
  const runStatusDemo = async () => {
    if (demoRunning) return;
    setDemoRunning(true);

    try {
      // Step 1: Set baseline
      const baseline = await sendMessage('Project status is active');
      if (baseline.events) {
        setEvents(prev => [...baseline.events.map(e => ({
          event_id: e.event_id,
          rule_id: e.rule_id,
          severity: e.severity,
          note: e.note,
          created_at: new Date(e.created_at).toLocaleString(),
        })), ...prev]);
      }

      await new Promise(r => setTimeout(r, 1000));

      // Step 2: Trigger drift
      const drift = await sendMessage('Project is now blocked');
      if (drift.events) {
        setEvents(prev => [...drift.events.map(e => ({
          event_id: e.event_id,
          rule_id: e.rule_id,
          severity: e.severity,
          note: e.note,
          created_at: new Date(e.created_at).toLocaleString(),
        })), ...prev]);

        const hasWarning = drift.events.some(e => e.severity === 'warn');
        if (hasWarning) {
          addBanner('Status drift detected: active → blocked', 'warning');
        }
      }

      addBanner('Status demo completed', 'success');
    } catch (error) {
      // Error already handled
    } finally {
      setDemoRunning(false);
    }
  };

  return (
    <div className="bg-slate-50 dark:bg-slate-900 min-h-screen font-sans text-slate-800 dark:text-slate-200">
      <div className="container mx-auto p-4 md:p-8">
        <header className="flex flex-col md:flex-row justify-between items-start md:items-center mb-6">
          <h1 className="text-3xl font-bold text-slate-900 dark:text-white mb-4 md:mb-0">
            Mirror OS – Pre-Beta Dashboard
          </h1>
          <div className="flex items-center space-x-4">
            <div className="relative">
              <select className="appearance-none bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-600 rounded-md py-2 pl-3 pr-8 text-sm leading-5 focus:outline-none focus:ring-2 focus:ring-indigo-500">
                <option>{sessionId}</option>
              </select>
              <ChevronDownIcon className="w-5 h-5 absolute top-1/2 right-2 -translate-y-1/2 text-slate-400 pointer-events-none" />
            </div>
            <span className="text-sm text-slate-500 dark:text-slate-400">
              Last Sync: {new Date().toLocaleString()}
            </span>
          </div>
        </header>

        {/* Banners - show first one only */}
        {banners.length > 0 && (
          <div className={`border-l-4 p-4 mb-6 rounded-r-lg flex justify-between items-center shadow-md ${
            banners[0].type === 'warning' ? 'bg-yellow-100 dark:bg-yellow-900 border-yellow-500 text-yellow-800 dark:text-yellow-200' :
            banners[0].type === 'error' ? 'bg-red-100 dark:bg-red-900 border-red-500 text-red-800 dark:text-red-200' :
            'bg-green-100 dark:bg-green-900 border-green-500 text-green-800 dark:text-green-200'
          }`}>
            <div className="flex items-center">
              <BellIcon className="h-6 w-6 mr-3" />
              <p>
                <span className="font-bold">
                  {banners[0].type === 'warning' ? 'Drift Notification' : 
                   banners[0].type === 'error' ? 'Error' : 'Success'}:
                </span> {banners[0].message}
              </p>
              {banners.length > 1 && (
                <span className="ml-3 text-sm opacity-75">+{banners.length - 1} more</span>
              )}
            </div>
            <button onClick={() => dismissBanner(banners[0].id)} className="p-1 rounded-full hover:bg-opacity-20 hover:bg-black">
              <XMarkIcon className="h-5 w-5" />
            </button>
          </div>
        )}
        
        <main className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-1 flex flex-col gap-6">
            {/* Demo Buttons */}
            <div className="bg-white dark:bg-slate-800 p-6 rounded-lg shadow-sm">
              <h2 className="text-lg font-semibold mb-4 text-slate-900 dark:text-white">Demo Scenarios</h2>
              <div className="space-y-3">
                <button
                  onClick={runBudgetDemo}
                  disabled={demoRunning}
                  className="w-full bg-blue-600 text-white font-semibold py-2 px-4 rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed dark:focus:ring-offset-slate-900"
                >
                  {demoRunning ? 'Running...' : 'Budget Drift Demo'}
                </button>
                <button
                  onClick={runDeadlineDemo}
                  disabled={demoRunning}
                  className="w-full bg-purple-600 text-white font-semibold py-2 px-4 rounded-md hover:bg-purple-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-purple-500 disabled:opacity-50 disabled:cursor-not-allowed dark:focus:ring-offset-slate-900"
                >
                  {demoRunning ? 'Running...' : 'Deadline Drift Demo'}
                </button>
                <button
                  onClick={runStatusDemo}
                  disabled={demoRunning}
                  className="w-full bg-green-600 text-white font-semibold py-2 px-4 rounded-md hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500 disabled:opacity-50 disabled:cursor-not-allowed dark:focus:ring-offset-slate-900"
                >
                  {demoRunning ? 'Running...' : 'Status Drift Demo'}
                </button>
              </div>
            </div>

            {/* Manual Message Input */}
            <div className="bg-white dark:bg-slate-800 p-6 rounded-lg shadow-sm">
              <h2 className="text-lg font-semibold mb-4 text-slate-900 dark:text-white">Message Input</h2>
              <textarea
                value={message}
                onChange={(e) => setMessage(e.target.value)}
                placeholder="Simulate user message, e.g., 'Let's increase the budget to 290000.'"
                className="w-full h-24 p-2 border border-slate-300 dark:border-slate-600 rounded-md bg-slate-50 dark:bg-slate-700 focus:outline-none focus:ring-2 focus:ring-indigo-500"
              />
              <button
                onClick={handleSendMessage}
                disabled={demoRunning}
                className="mt-4 w-full bg-indigo-600 text-white font-semibold py-2 px-4 rounded-md hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:opacity-50 disabled:cursor-not-allowed dark:focus:ring-offset-slate-900"
              >
                Send Message
              </button>
            </div>

            {/* Status */}
            <div className="bg-white dark:bg-slate-800 p-6 rounded-lg shadow-sm">
              <h2 className="text-lg font-semibold mb-4 text-slate-900 dark:text-white">Current Session</h2>
              <ul className="space-y-3 text-sm">
                <li className="flex justify-between items-center">
                  <span className="text-slate-500 dark:text-slate-400">Session ID</span>
                  <span className="font-mono text-slate-900 dark:text-white">{sessionId}</span>
                </li>
                <li className="flex justify-between items-center">
                  <span className="text-slate-500 dark:text-slate-400">Turn ID</span>
                  <span className="font-mono text-slate-900 dark:text-white">{turnIdRef.current}</span>
                </li>
              </ul>
            </div>
          </div>

          <div className="lg:col-span-2 bg-white dark:bg-slate-800 p-6 rounded-lg shadow-sm">
            <h2 className="text-lg font-semibold mb-4 text-slate-900 dark:text-white">Ledger Events</h2>
            <div className="overflow-x-auto">
              <table className="w-full text-sm text-left">
                <thead className="border-b border-slate-200 dark:border-slate-700 text-xs text-slate-500 dark:text-slate-400 uppercase">
                  <tr>
                    <th scope="col" className="px-4 py-3">Event ID</th>
                    <th scope="col" className="px-4 py-3">Rule</th>
                    <th scope="col" className="px-4 py-3">Severity</th>
                    <th scope="col" className="px-4 py-3">Note</th>
                    <th scope="col" className="px-4 py-3">Timestamp</th>
                  </tr>
                </thead>
                <tbody>
                  {events.map((event, index) => (
                    <tr key={`${event.event_id}-${index}`} className="border-b border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-700/50">
                      <td className="px-4 py-3 font-mono text-xs">{event.event_id}</td>
                      <td className="px-4 py-3 font-mono text-xs">{event.rule_id}</td>
                      <td className="px-4 py-3">
                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                          severityConfig[event.severity.toLowerCase()]?.badge || severityConfig.info.badge
                        }`}>
                          {severityConfig[event.severity.toLowerCase()]?.icon || severityConfig.info.icon} {event.severity}
                        </span>
                      </td>
                      <td className="px-4 py-3">{event.note}</td>
                      <td className="px-4 py-3 font-mono text-xs">{event.created_at}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </main>
      </div>
    </div>
  );
}