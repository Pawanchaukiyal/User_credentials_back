
// All the Api Error handle here 

//it inherits from the built-in Error class, which provides basic error handling functionalities in JavaScript.
class ApiError extends Error {
  constructor(
    statusCode,
    message = "Something went wrong",
    errors = [],
    stack = ""
  ) {
    super(message);//This line calls the parent class (Error) constructor, passing the provided message as an argument. This ensures that the ApiError inherits error handling capabilities from the Error class. 
    this.statusCode = statusCode;
    this.data = null;
    this.message = message;
    this.success = false;
    this.errors = errors;

    if (stack) {//This block deals with the error stack trace, which provides information about where the error originated in the code.
      this.stack = stack;
    } else {
      Error.captureStackTrace(this, this.constructor);
    }
  }
}

export { ApiError };