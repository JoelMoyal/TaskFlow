import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';

function App() {
  return (
    <Router>
      <div className="min-h-screen bg-gray-100 dark:bg-gray-900 text-gray-900 dark:text-white">
        <Routes>
          <Route path="/" element={<div className="p-8 text-center">Welcome to TaskFlow</div>} />
        </Routes>
      </div>
    </Router>
  );
}

export default App;
