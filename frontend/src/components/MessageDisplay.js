import React, { useEffect, useRef, useState } from 'react';
import parse from 'html-react-parser';

import './MessageDisplay.css';

const MessageDisplay = ({ chatHistory }) => {
  const messagesEndRef = useRef(null);
  const eventSourceRef = useRef(null);
  const [streamingMessages, setStreamingMessages] = useState([]);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [chatHistory, streamingMessages]);

  const startStreaming = () => {
    eventSourceRef.current = new EventSource('http://0.0.0.0:8000/api/streamlogs/');
    eventSourceRef.current.onmessage = (event) => {
      setStreamingMessages(currentMessages => [...currentMessages, event.data]);
    };
    eventSourceRef.current.onerror = (error) => {
      console.error('Stream error:', error);
      eventSourceRef.current.close();
    };
  };
  const stopStreaming = () => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      setStreamingMessages([]);
      eventSourceRef.current = null;
    }
  };
  useEffect(() => {
    const isLoadingMessagePresent = chatHistory.some(message => message.loading);
    if (isLoadingMessagePresent && !eventSourceRef.current) {
      startStreaming();
    }
    return () => {
      stopStreaming();
    };
  }, [chatHistory]);

  return (
    <div className="message-display">
      {chatHistory.map((message, index) => (
        <div key={index} className={`message ${message.sender}`}>
          <div className="message-text">
          {message.loading ? (
            <>
                <div>
                  {streamingMessages.map((msg, idx) => (
                    <div key={idx}>{msg}</div>
                  ))}
                </div>
                <span className="terminal"></span>
                <span className="caret"></span>
              </>
            ) : (
              parse(message.text)
            )}
          </div>
          {message.sender === 'user' && !message.loading && (
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
