import axios from 'axios';

const API_URL = '/api/tasks'; // Adjust the API URL as necessary

export const getTasks = async (filters) => {
  // ... existing code ...
};

export const createTask = async (taskData) => {
  const response = await axios.post(API_URL, taskData);
  return response;
};

// ... other service functions ... 