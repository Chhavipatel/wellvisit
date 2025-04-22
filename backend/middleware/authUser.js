
import jwt from 'jsonwebtoken'

// user authentication middleware
const authUser = async (req, res, next) => {
    const { token } = req.headers
    if (!token) {
        return res.status(401).json({ success: false, message: 'Not Authorized: No token provided' })
    }
    try {
        // Log the secret for debugging (remove in production)
        console.log("JWT_SECRET being used:", process.env.JWT_SECRET);
        
        const token_decode = jwt.verify(token, process.env.JWT_SECRET)
        req.body.userId = token_decode.id
        next()
    } catch (error) {
        console.error("JWT Verification Error:", {
            name: error.name,
            message: error.message,
            token: token // Be cautious with logging full tokens in production
        })
        
        // Provide more specific error responses
        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({ 
                success: false, 
                message: 'Invalid token. Please login again.',
                error: error.message 
            })
        } else if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ 
                success: false, 
                message: 'Token expired. Please login again.' 
            })
        }
        
        res.status(500).json({ 
            success: false, 
            message: 'Authentication error',
            error: error.message 
        })
    }
}

export default authUser;