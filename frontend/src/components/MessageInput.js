import React, { useState } from 'react';
import './MessageInput.css';

const MessageInput = ({ onNewMessage }) => {
  const [message, setMessage] = useState('');

  const handleSubmit = (e) => {
    e.preventDefault();
    if (message.trim()) {
      onNewMessage(message);
      setMessage('');
    }
  };

  return (
    <form onSubmit={handleSubmit} className="message-input sm:flex sm:items-center">
      <input
        className="flex-grow p-2 border border-green-500 bg-black text-green-500"
        type="text"
        value={message}
        onChange={(e) => setMessage(e.target.value)}
        placeholder="Type a message..."
      />
      <button type="submit" className="px-4 py-2 border border-green-500 bg-green-500 text-black hover:bg-green-600">Send</button>
    </form>
  );
};

export default MessageInput;
