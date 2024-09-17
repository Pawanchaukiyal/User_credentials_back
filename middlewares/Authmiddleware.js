import { ApiError } from "../utils/ApiErrors.js";
import jwt from "jsonwebtoken";
import { User } from "../models/user.model.js";
// import { asyncHandler } from "../utils/asyncHandler.js";

// export const verifyJWT = asyncHandler(async (req, res, next) => {
//   // Extract token from cookies or Authorization header
//   const token = req.cookies?.accessToken || req.header('Authorization')?.replace('Bearer ', '');

//   if (!token) {
//     // No token found
//     throw new ApiError(401, "Unauthorized request - No token provided");
//   }

//   try {
//     // Verify the JWT token
//     const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);

//     // Fetch user by ID from decoded token
//     const user = await User.findById(decodedToken?._id).select('-password -refreshToken');

//     if (!user) {
//       // If no user is found in the database with the decoded token's ID
//       throw new ApiError(401, "Invalid Access Token - User not found");
//     }

//     // Attach the user object to the request
//     req.user = user;
//     next(); // Continue to the next middleware

//   } catch (error) {
//     if (error.name === 'TokenExpiredError') {
//       throw new ApiError(401, "Access Token expired. Please log in again.");
//     }
//     if (error.name === 'JsonWebTokenError') {
//       throw new ApiError(401, "Invalid Access Token. Please log in again.");
//     }
//     // Any other errors
//     throw new ApiError(401, "Unauthorized request");
//   }
// });




export const verifyJWT = async (req, res, next) => {
  const token = req.cookies?.accessToken || req.header('Authorization')?.replace('Bearer ', '');

  if (!token) {
    return next(new ApiError(401, "Unauthorized request - No token provided"));
  }

  try {
    const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    const user = await User.findById(decodedToken._id).select('-password -refreshToken');

    if (!user) {
      return next(new ApiError(401, "Invalid Access Token - User not found"));
    }

    req.user = user;
    next();

  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return next(new ApiError(401, "Access Token expired. Please log in again."));
    }
    if (error.name === 'JsonWebTokenError') {
      return next(new ApiError(401, "Invalid Access Token. Please log in again."));
    }
    return next(new ApiError(401, "Unauthorized request"));
  }
};
