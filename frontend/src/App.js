import React, { useState, useEffect } from 'react';
import ChatWindow from './components/ChatWindow';
import './App.css';

function App() {
  const [chatHistory, setChatHistory] = useState([]);

  useEffect(() => {
    const savedChatHistory = localStorage.getItem('chatHistory');
    if (savedChatHistory) {
      setChatHistory(JSON.parse(savedChatHistory));
    }
  }, []);

  useEffect(() => {
    localStorage.setItem('chatHistory', JSON.stringify(chatHistory));
  }, [chatHistory]);

  const handleNewMessage = async (message) => {
    const newMessage = { text: message, sender: 'user', timestamp: new Date() };
    const loadingMessage = { id: 'loading', text: '', sender: 'bot', timestamp: new Date(), loading: true };
    setChatHistory([...chatHistory, newMessage, loadingMessage]);
    try {
      const transformedHistory = [...chatHistory, newMessage]
      .map(msg => ({
        role: msg.sender === 'user' ? 'user' : 'assistant',
        content: msg.text
      }));
      const response = await fetch('http://0.0.0.0:8000/networkgpt/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
        body: JSON.stringify({ message: transformedHistory, model: "gpt-3.5-turbo-1106" })
      });      
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      const data = await response.json();
      setChatHistory(currentChatHistory => currentChatHistory.filter(msg => msg.id !== 'loading'));
      const botResponse = { text: data.response.replace(/\n/g, '<br/>'), sender: 'bot', timestamp: new Date() };
      setChatHistory(chat => [...chat, botResponse]);

    } catch (error) {
      console.error("Failed to send message: ", error);
      setChatHistory(currentChatHistory => currentChatHistory.filter(msg => msg.id !== 'loading'));
      const botResponse = { text: 'Failed to get response', sender: 'bot', timestamp: new Date() };
      setChatHistory(chat => [...chat, botResponse]);
    }
  };

  const asciiArtTitle = `
  ##    ## ######## ######## ##      ##  #######  ########  ##    ##        ######   ########  ######## 
  ###   ## ##          ##    ##  ##  ## ##     ## ##     ## ##   ##        ##    ##  ##     ##    ##    
  ####  ## ##          ##    ##  ##  ## ##     ## ##     ## ##  ##         ##        ##     ##    ##    
  ## ## ## ######      ##    ##  ##  ## ##     ## ########  #####          ##   #### ########     ##    
  ##  #### ##          ##    ##  ##  ## ##     ## ##   ##   ##  ##         ##    ##  ##           ##    
  ##   ### ##          ##    ##  ##  ## ##     ## ##    ##  ##   ##        ##    ##  ##           ##    
  ##    ## ########    ##     ###  ###   #######  ##     ## ##    ##        ######   ##           ##    
`;

  return (
    <div className="App h-screen flex flex-col sm:p-5 p-2">
      <div className="hidden sm:block">
        <pre className="ascii-art whitespace-pre font-terminal text-terminal-green bg-black p-2.5">{asciiArtTitle}</pre>
      </div>
      <div className="sm:hidden">
        <pre className="mini-ascii-art whitespace-pre font-terminal text-terminal-green bg-black p-2.5">{asciiArtTitle}</pre>
      </div>
      <ChatWindow chatHistory={chatHistory} onNewMessage={handleNewMessage} />
    </div>
  );
}


export default App;
