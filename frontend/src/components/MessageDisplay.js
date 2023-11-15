import React, { useEffect, useRef } from 'react';
import './MessageDisplay.css';

const MessageDisplay = ({ chatHistory }) => {
  const messagesEndRef = useRef(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [chatHistory]);

  return (
    <div className="message-display">
      {chatHistory.map((message, index) => (
        <div key={index} className={`message ${message.sender}`}>
          <div className="message-text">{message.text}</div>
          {message.sender === 'user' && (
            <div className="message-time">
              {new Date(message.timestamp).toLocaleTimeString()}
            </div>
          )}
        </div>
      ))}
      <div ref={messagesEndRef} />
    </div>
  );
};

export default MessageDisplay;
