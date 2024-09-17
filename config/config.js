export const corsOptions = {
  origin: process.env.frontend_url, // Update to match your frontend URL
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  credentials: true, // This allows cookies to be sent from the frontend
  allowedHeaders: ['Content-Type', 'Authorization'],
};
