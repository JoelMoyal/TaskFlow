import React, { useState, useEffect } from 'react';
import { getTasks, createTask } from '../services/taskService';
import TaskForm from '../components/TaskForm';
import Layout from '../components/Layout';
import TaskList from '../components/TaskList';
import FilterBar from '../components/FilterBar';
import { useAuth } from '../contexts/AuthContext';

const Dashboard = () => {
  const [tasks, setTasks] = useState([]);
  const [categories, setCategories] = useState([]);
  const [filters, setFilters] = useState({ category: '', priority: '', status: '', search: '' });
  const [isAddingTask, setIsAddingTask] = useState(false);
  const [loading, setLoading] = useState(true);
  const { currentUser } = useAuth();

  useEffect(() => {
    const loadData = async () => {
      try {
        setLoading(true);
        const tasksResponse = await getTasks(filters);
        setTasks(tasksResponse.data);
        // Assume categories are fetched from another service
      } catch (error) {
        console.error('Failed to load dashboard data', error);
      } finally {
        setLoading(false);
      }
    };

    loadData();
  }, [filters]);

  const handleAddTask = async (newTask) => {
    try {
      const createdTask = await createTask(newTask);
      setTasks([createdTask.data, ...tasks]);
      setIsAddingTask(false);
    } catch (error) {
      console.error('Failed to add task', error);
    }
  };

  return (
    <Layout>
      <div className="container mx-auto py-6 px-4">
        <h1 className="text-2xl font-bold mb-4">My Tasks</h1>
        <button onClick={() => setIsAddingTask(true)} className="bg-blue-600 text-white py-2 px-4 rounded">
          Add Task
        </button>

        {isAddingTask && (
          <TaskForm 
            categories={categories}
            onSave={handleAddTask}
            onCancel={() => setIsAddingTask(false)}
          />
        )}

        {loading ? (
          <div>Loading...</div>
        ) : (
          <TaskList tasks={tasks} />
        )}
      </div>
    </Layout>
  );
};

export default Dashboard; 