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

  const handleNewMessage = (message) => {
    const newMessage = { text: message, sender: 'user', timestamp: new Date() };
    setChatHistory([...chatHistory, newMessage]);
    // Here you would call your GPT API
    // Simulate a response for now
    setTimeout(() => {
      const botResponse = { text: 'Simulated Response', sender: 'bot', timestamp: new Date() };
      setChatHistory(chat => [...chat, botResponse]);
    }, 10);
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
      <div className="sm:hidden text-2xl font-mono text-terminal-green bg-black p-2.5">
        Network GPT
      </div>
      <ChatWindow chatHistory={chatHistory} onNewMessage={handleNewMessage} />
    </div>
  );
}


export default App;
