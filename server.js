const express = require('express');
const mongoose = require('mongoose');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcrypt');
const port = 3019;

const app = express();
app.use(express.static(__dirname));
app.use(express.urlencoded({ extended: true }));
app.use(express.json()); // Middleware to parse JSON bodies

// Session management
app.use(session({
    secret: 'your_secret_key',
    resave: false,
    saveUninitialized: true,
}));

// MongoDB connection
mongoose.connect('mongodb://127.0.0.1:27017/student_info');

const db = mongoose.connection;

// Error and connection handlers
db.on('error', (error) => console.error('MongoDB connection error:', error));
db.once('open', () => {
    console.log("MongoDB connection successful");
});

// User schema and model
const userSchema = new mongoose.Schema({
    Name: String,
    email: { type: String, unique: true }, // Ensure email is unique
    password: String,
});

const Users = mongoose.model("User", userSchema);

// Routes
app.get('/', (req, res) => {
    if (req.session.user) {
        res.sendFile(path.join(__dirname, 'landing.html'));
    } else {
        res.redirect('/login');
    }
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html'));
});

app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'register.html'));
});

// Registration route
app.post('/register', async (req, res) => {
    try {
        const { Name, email, password } = req.body;
        console.log('Received data:', { Name, email, password }); // Log the received data
        
        // Check if user already exists
        const existingUser = await Users.findOne({ email });
        if (existingUser) {
            return res.status(400).send('User with this email already exists.');
        }

        // Ensure password is not undefined
        if (!password) {
            return res.status(400).send('Password is required');
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);
        console.log('Hashed password:', hashedPassword); // Log the hashed password

        const user = new Users({ Name, email, password: hashedPassword });
        await user.save();
        console.log('User registered:', user);
        res.redirect('/login');
    } catch (error) {
        console.error('Error registering user:', error);
        res.status(500).send('Error registering user');
    }
});

// Login route
app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await Users.findOne({ email });
        
        if (user && await bcrypt.compare(password, user.password)) {
            req.session.user = user; // Save user session
            res.redirect('/'); // Redirect to landing page upon successful login
        } else {
            res.status(401).send('Invalid email or password');
        }
    } catch (error) {
        console.error('Error logging in:', error);
        res.status(500).send('Error logging in');
    }
});

// Logout route
app.post('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).send('Error logging out');
        }
        res.redirect('/login');
    });
});

// Start server
app.listen(port, () => {
    console.log("Server started on port", port);
});







/**
const express = require('express');
const mongoose = require('mongoose');
const path = require('path');
const bcrypt = require('bcrypt');  // Import bcrypt for password hashing
const port = 3020;

const app = express();
app.use(express.static(__dirname));
app.use(express.urlencoded({ extended: true }));

mongoose.connect('mongodb://127.0.0.1:27017/Customer')
const db = mongoose.connection;

// Error and connection handlers
db.on('error', (error) => console.error('MongoDB connection error:', error));
db.once('open', () => {
    console.log("MongoDB connection successful");
});

// User Schema with password hashing logic
const userSchema = new mongoose.Schema({
    Name: String,
    email: String,
    password: String
});

// Pre-save hook to hash passwords
userSchema.pre('save', async function (next) {
    try {
        // Only hash the password if it has been modified (or is new)
        if (this.isModified('password')) {
            const salt = await bcrypt.genSalt(10);  // Generate salt with 10 rounds
            this.password = await bcrypt.hash(this.password, salt);  // Hash the password
        }
        next();  // Continue to save the user
    } catch (error) {
        next(error);  // Pass error to the next middleware
    }
});

const Users = mongoose.model("User", userSchema);  // Create the User model

// Serve login.html
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html'));
});

// Serve register.html
app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'register.html'));
});

// Post route to handle form submission and password hashing
app.post('/post', async (req, res) => {
    try {
        const { Name, email, password } = req.body;

        // Create a new user instance
        const user = new Users({ Name, email, password });

        // Save the user to MongoDB
        await user.save();
        console.log('User saved:', user);

        res.send("Form submitted successfully");
    } catch (error) {
        console.error('Error saving user:', error);
        res.status(500).send('Error saving user');
    }
});

// Start the server
app.listen(port, () => {
    console.log("Server started on port", port);
});



*/

/**const express = require('express');
const mongoose = require('mongoose');
const path = require('path');
const bcrypt = require('bcryptjs'); // Use bcryptjs
const port = 3019;

const app = express();
app.use(express.static(__dirname));
app.use(express.urlencoded({ extended: true }));

mongoose.connect('mongodb://127.0.0.1:27017/Customer');
const db = mongoose.connection;

// Error and connection handlers
db.on('error', (error) => console.error('MongoDB connection error:', error));
db.once('open', () => {
    console.log("MongoDB connection successful");
});

const userSchema = new mongoose.Schema({
    Name: String,
    email: String,
    password: String
});

const Users = mongoose.model("User", userSchema);

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html'));
});

app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'register.html'));
});

app.post('/post', async (req, res) => {
    try {
        const { Name, email, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10); // Hash password
        const user = new Users({ Name, email, password: hashedPassword }); // Store hashed password
        await user.save();
        console.log('User saved:', user);
        res.send("Form submitted successfully");
    } catch (error) {
        console.error('Error saving user:', error);
        res.status(500).send('Error saving user');
    }
});

app.listen(port, () => {
    console.log("Server started on port", port);
});**/


/** const express = require('express');
const mongoose = require('mongoose');
const path = require('path');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer'); // For sending emails
const crypto = require('crypto'); // For generating random OTPs
const port = 3019;

const app = express();
app.use(express.static(__dirname));
app.use(express.urlencoded({ extended: true }));

mongoose.connect('mongodb://127.0.0.1:27017/Customer');
const db = mongoose.connection;

db.on('error', (error) => console.error('MongoDB connection error:', error));
db.once('open', () => {
    console.log("MongoDB connection successful");
});

// User Schema
const userSchema = new mongoose.Schema({
    Name: String,
    email: String,
    password: String, // Password will be stored as a hashed value
    otp: String, // OTP for password reset
    otpExpiration: Date // OTP expiration time
});

const Users = mongoose.model("User", userSchema);

// Nodemailer Transporter for sending emails
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'your-email@gmail.com', // replace with your email
        pass: 'your-email-password' // replace with your email password
    }
});

// Send Email Function
const sendOTPEmail = (email, otp) => {
    const mailOptions = {
        from: 'your-email@gmail.com',
        to: email,
        subject: 'Password Reset OTP',
        text: `Your OTP for password reset is: ${otp}. It is valid for 10 minutes.`
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.error('Error sending email:', error);
        } else {
            console.log('Email sent: ' + info.response);
        }
    });
};

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html'));
});

app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'register.html'));
});

app.get('/landing_page', (req, res) => {
    res.sendFile(path.join(__dirname, 'landing_page.html'));
});

app.get('/forgot', (req, res) => {
    res.sendFile(path.join(__dirname, 'forgot.html'));
});

app.get('/reset', (req, res) => {
    res.sendFile(path.join(__dirname, 'reset.html'));
});

// Handle Registration
app.post('/register', async (req, res) => {
    try {
        const { Name, email, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10); // Hash password
        const user = new Users({ Name, email, password: hashedPassword });
        await user.save();
        console.log('User registered:', user);

        // Redirect to login page after successful registration
        res.redirect('/');
    } catch (error) {
        console.error('Error registering user:', error);
        res.status(500).send('Error registering user');
    }
});

// Handle Login
app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Find the user by email
        const user = await Users.findOne({ email });
        if (!user) {
            return res.status(400).send("User not found");
        }

        // Compare the provided password with the stored hashed password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).send("Invalid password");
        }

        // Successful login, redirect to landing page
        console.log('User logged in:', user);
        res.redirect('/landing_page'); // Redirect to landing page
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).send('Error during login');
    }
});

// Handle Forgot Password - Generate OTP
app.post('/send-otp', async (req, res) => {
    const { email } = req.body;
    
    if (!email) {
        return res.status(400).send("Email is required");
    }

    // Generate a random OTP (example: 6-digit OTP)
    const otp = Math.floor(100000 + Math.random() * 900000);
    
    // Logic to send the OTP via email goes here (using nodemailer or similar)
    // Example using nodemailer:
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: 'your-email@gmail.com',
            pass: 'your-email-password',
        },
    });

    const mailOptions = {
        from: 'your-email@gmail.com',
        to: email,
        subject: 'Your OTP Code',
        text: `Your OTP code is ${otp}`,
    };

    try {
        await transporter.sendMail(mailOptions);
        console.log('OTP sent to:', email);

        // You could store the OTP in your database for validation
        // For now, we'll just send a success response
        res.status(200).send('OTP sent successfully');
    } catch (error) {
        console.error('Error sending OTP:', error);
        res.status(500).send('Error sending OTP');
    }
});


// Handle OTP Verification and Reset Password
app.post('/reset', async (req, res) => {
    try {
        const { email, otp, newPassword } = req.body;
        const user = await Users.findOne({ email });

        if (!user) {
            return res.status(400).send("User not found");
        }

        // Check if the OTP is valid and not expired
        if (user.otp !== otp || Date.now() > user.otpExpiration) {
            return res.status(400).send("Invalid or expired OTP");
        }

        // Hash the new password and update the user's password
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedPassword;
        user.otp = undefined; // Clear OTP
        user.otpExpiration = undefined; // Clear OTP expiration
        await user.save();

        res.send("Password has been reset successfully.");
    } catch (error) {
        console.error('Error resetting password:', error);
        res.status(500).send('Error resetting password');
    }
});

app.listen(port, () => {
    console.log("Server started on port", port);
});

*/