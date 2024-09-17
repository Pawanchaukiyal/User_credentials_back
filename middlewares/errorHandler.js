const errorHandler = (err, req, res, next) => {
    // Log the error for debugging purposes
    console.error('Error occurred:', err);
  
    // Set the response status code and send the error message
    res.status(err.statusCode || 500).json({
      success: false,
      message: err.message || 'Internal Server Error',
      ...(err.errors && { errors: err.errors }) // Include additional errors if present
    });
  };
  
  export default errorHandler;