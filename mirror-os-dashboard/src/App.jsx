// src/App.jsx

import React, { useState } from 'react';
import { ChevronDownIcon, BellIcon, XMarkIcon } from '@heroicons/react/24/solid';

// Mock Ledger event data
const mockEvents = [
  { event_id: 'NUM-001-4-A1B2', rule_id: 'NUM-001', severity: 'WARN', note: 'Budget increased from baseline.', created_at: '2025-09-30 10:30:15' },
  { event_id: 'DATE-001-7-C3D4', rule_id: 'DATE-001', severity: 'INFO', note: 'Deadline is within the acceptable range.', created_at: '2025-09-30 10:29:55' },
  { event_id: 'NUM-001-3-E5F6', rule_id: 'NUM-001', severity: 'INFO', note: 'Initial budget set.', created_at: '2025-09-29 18:05:10' },
  { event_id: 'SYS-INIT-1-G7H8', rule_id: 'SYS-INIT', severity: 'INFO', note: 'Session demo-001 initialized.', created_at: '2025-09-29 18:00:00' },
];

// Severity color configuration
const severityConfig = {
  INFO: {
    badge: 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300',
    icon: 'ℹ️',
  },
  WARN: {
    badge: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-300',
    icon: '⚠️',
  },
  ERROR: {
    badge: 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300',
    icon: '❌',
  },
};

export default function App() {
  const [message, setMessage] = useState('');
  const [events, setEvents] = useState(mockEvents);
  const [driftNotification, setDriftNotification] = useState('Budget drift detected: baseline 280000 -> current 290000');

  // Handle message sending (simulation)
  const handleSendMessage = () => {
    if (!message.trim()) return;
    console.log('Sending message:', message);
    const newEvent = {
      event_id: `NUM-001-${events.length + 1}-SIMU`,
      rule_id: 'NUM-001',
      severity: 'WARN',
      note: `User input triggered budget check: "${message}"`,
      created_at: new Date().toISOString().slice(0, 19).replace('T', ' '),
    };
    setEvents([newEvent, ...events]);
    setMessage('');
    setDriftNotification(`Budget drift detected: ${message}`);
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
                <option>demo-001</option>
                <option>session-alpha</option>
                <option>test-run-42</option>
              </select>
              <ChevronDownIcon className="w-5 h-5 absolute top-1/2 right-2 -translate-y-1/2 text-slate-400 pointer-events-none" />
            </div>
            <span className="text-sm text-slate-500 dark:text-slate-400">
              Last Sync: 2025-09-30 10:35:12
            </span>
          </div>
        </header>

        {driftNotification && (
          <div className="bg-yellow-100 dark:bg-yellow-900 border-l-4 border-yellow-500 text-yellow-800 dark:text-yellow-200 p-4 mb-6 rounded-r-lg flex justify-between items-center shadow-md">
            <div className="flex items-center">
              <BellIcon className="h-6 w-6 mr-3 text-yellow-500" />
              <p>
                <span className="font-bold">Drift Notification:</span> {driftNotification}
              </p>
            </div>
            <button onClick={() => setDriftNotification(null)} className="p-1 rounded-full hover:bg-yellow-200 dark:hover:bg-yellow-800">
              <XMarkIcon className="h-5 w-5" />
            </button>
          </div>
        )}
        
        <main className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-1 flex flex-col gap-6">
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
                className="mt-4 w-full bg-indigo-600 text-white font-semibold py-2 px-4 rounded-md hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 dark:focus:ring-offset-slate-900"
              >
                Send Message
              </button>
            </div>

            <div className="bg-white dark:bg-slate-800 p-6 rounded-lg shadow-sm">
              <h2 className="text-lg font-semibold mb-4 text-slate-900 dark:text-white">Status</h2>
              <ul className="space-y-3 text-sm">
                <li className="flex justify-between items-center">
                  <span className="text-slate-500 dark:text-slate-400">Budget</span>
                  <span className="font-mono text-slate-900 dark:text-white">280000 <span className="text-xs text-slate-400">(baseline)</span></span>
                </li>
                <li className="flex justify-between items-center">
                  <span className="text-slate-500 dark:text-slate-400">Deadline</span>
                  <span className="font-mono text-slate-900 dark:text-white">2025-10-15 <span className="text-xs text-slate-400">(baseline)</span></span>
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
                  {events.map((event) => (
                    <tr key={event.event_id} className="border-b border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-700/50">
                      <td className="px-4 py-3 font-mono text-xs">{event.event_id}</td>
                      <td className="px-4 py-3 font-mono text-xs">{event.rule_id}</td>
                      <td className="px-4 py-3">
                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${severityConfig[event.severity].badge}`}>
                          {severityConfig[event.severity].icon} {event.severity}
                        </span>
                      </td>
                      <td className="px-4 py-3">{event.note}</td>
                      <td className="px-4 py-3 font-mono">{event.created_at}</td>
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