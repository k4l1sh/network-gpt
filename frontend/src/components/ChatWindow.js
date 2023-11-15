import React from 'react';
import MessageInput from './MessageInput';
import MessageDisplay from './MessageDisplay';
import './ChatWindow.css';

const ChatWindow = ({ chatHistory, onNewMessage }) => {
  return (
    <div className="chat-window flex-grow overflow-y-auto sm:mb-5 mb-3">
      <MessageDisplay chatHistory={chatHistory} />
      <MessageInput onNewMessage={onNewMessage} />
    </div>
  );
};

export default ChatWindow;
