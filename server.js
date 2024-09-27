require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { createClient } = require('@supabase/supabase-js');

// Initialize Supabase client
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

const uploadsDir = path.join(__dirname, 'uploads');

if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir);
}

const app = express();
const port = 5000;

app.use(cors({ origin: 'http://localhost:3000' }));
app.use(bodyParser.json());
app.use('/uploads', express.static(uploadsDir));

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadsDir);
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname));
    },
});

const upload = multer({ storage });

// Generate JWT token
const generateToken = (user) => {
    return jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '3h' });
};

// Login endpoint
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const { data: user, error } = await supabase
            .from('users')
            .select('*')
            .eq('email', email)
            .single();

        if (error || !user) {
            return res.status(401).json({ message: 'Invalid email or password.' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (isMatch) {
            const token = generateToken(user);
            return res.status(200).json({ message: 'Login successful!', token });
        } else {
            return res.status(401).json({ message: 'Invalid email or password.' });
        }
    } catch (error) {
        console.error('Login error:', error);
        return res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// Middleware to authenticate the token
const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Unauthorized: No token provided' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Forbidden: Token verification failed' });
        }
        req.user = user;
        next();
    });
};

// Add user function
async function addUser(name, email, password) {
    const hashedPassword = await bcrypt.hash(password, 10);
    const { data, error } = await supabase
        .from('users')
        .insert([{ name, email, password: hashedPassword }]);

    if (error) {
        console.error('Error inserting data:', error);
        throw new Error('Error inserting user data');
    } else {
        console.log('User added:', data);
    }
}

// Add user endpoint
app.post('/api/add-user', async (req, res) => {
    const { name, email, password } = req.body;
    try {
        await addUser(name, email, password);
        res.status(201).json({ message: 'User added successfully' });
    } catch (error) {
        console.error('Error adding user:', error); // Log the error
        res.status(500).json({ message: 'Error adding user', error });
    }
});

async function addUser(name, email, password) {
    const hashedPassword = await bcrypt.hash(password, 10);
    const { data, error } = await supabase
      .from('users')
      .insert([
        { name: name, email: email, password: hashedPassword }
      ]);

    if (error) {
        console.error('Error inserting data:', error);
        throw new Error(error.message); // Throwing the specific Supabase error
    } else {
        console.log('User added:', data);
    }
}



// Start the server
app.listen(port, '0.0.0.0', () => {
    console.log(`Server running on http://192.168.2.202:${port}`);
});
