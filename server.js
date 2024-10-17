const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs'); // Import bcryptjs for password hashing
const jwt = require('jsonwebtoken'); // Import jsonwebtoken
require('dotenv').config();

const app = express();
const PORT = process.env.SERVER_PORT || 5000; // Default to port 5000 if not set

// Middleware--------------------------------------
app.use(cors({
  origin: 'https://djprimetime.onrender.com', // Allow requests only from this origin
  methods: ['GET', 'POST', 'PUT', 'DELETE'], // Specify allowed methods
  credentials: true // If you're using cookies or authentication tokens
}));

app.use(express.json());

// MongoDB Connection---------------------------------------------------------------------------
mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
    .then(() => console.log('MongoDB connected'))
    .catch((err) => console.error('MongoDB connection error:', err));

// User Model--------------------------------------------------------------
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    createdAt: { type: Date, default: Date.now },
});

const User = mongoose.model('SpotifyUser', UserSchema);

const trackSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'SpotifyUser', required: true }, // Use ObjectId to reference User
  spotifyId: { type: String, required: true },
  name: { type: String, required: true },
  artist: { type: String, required: true },
  album: { type: String, required: true },
  imageUrl: { type: String, required: true },
}, { timestamps: true }); // Optional: add timestamps for createdAt and updatedAt

const Track = mongoose.model('SpotifyTrack', trackSchema);


// Middleware to check if email already exists
const checkEmailExists = async (req, res, next) => {
    try {
        const { email } = req.body;
        const existingUser = await User.findOne({ email });

        if (existingUser) {
            return res.status(400).json({ message: 'Email already in use. Please use another email.' });
        }

        next();
    } catch (error) {
        console.error('Error checking email:', error);
        res.status(500).json({ error: 'Error checking email' });
    }
};

// Register route
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;

        // Validate required fields
        if (!username || !email || !password) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        // Check if the email or username already exists
        const existingUser = await User.findOne({ $or: [{ username }, { email }] });
        if (existingUser) {
            const message = existingUser.email === email
                ? 'Email already in use'
                : 'Username already taken';
                
            return res.status(409).json({ error: message });
        }

        // Hash the password before saving
        const hashedPassword = await bcrypt.hash(password, 10); // Hashing with a salt rounds of 10
        const newUser = new User({ username, email, password: hashedPassword });
        await newUser.save();

        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        console.error('Error registering user:', error);
        res.status(500).json({ error: 'Error registering user' });
    }
});



app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Check if the username and password are provided
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    const user = await User.findOne({ username });

    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Compare hashed password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generate a JWT token
    const token = jwt.sign(
      { userId: user._id },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    // Send back the token
    res.status(200).json({ message: 'User logged in successfully', token });
  } catch (error) {
    console.error('Error logging in:', error);
    res.status(500).json({ error: 'Error logging in' });
  }
});























// Login route
app.post('/api/music', async (req, res) => {
  try {
    // Extracting the request body
    const { userId, spotifyId, name, artist, album, imageUrl } = req.body;

    // Validate required fields
    if (!userId || !spotifyId || !name || !artist || !album || !imageUrl) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    // Check if userId is a valid ObjectId
    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({ error: 'Invalid userId format' });
    }

    // Create a new track object using the data from the request body
    const newTrack = new Track({ 
      userId, 
      spotifyId, 
      name, 
      artist, 
      album, 
      imageUrl 
    });

    // Save the track to the database
    await newTrack.save();
    res.status(201).json({ message: 'Track added successfully' });
  } catch (error) {
    console.error('Error adding track:', error);
    res.status(500).json({ error: 'Error adding track' });
  }
});

const authenticateJWT = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  console.log(token)
  if (!token) {
      return res.sendStatus(401); // Unauthorized
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
      if (err) {
          return res.sendStatus(403); // Forbidden
      }
      req.userId = user.userId; // Save user ID for later use
      next();
  });
};


// Route to get saved tracks for the logged-in user
app.get('/api/music/tracks', authenticateJWT, async (req, res) => {
    try {
        // Find tracks for the authenticated user by userId
        const tracks = await Track.find({ userId: req.userId });

        // Check if any tracks were found
        if (tracks.length === 0) {
            return res.status(404).json({ message: 'No tracks found for this user.' });
        }

        // Return the found tracks
        res.status(200).json(tracks);
    } catch (error) {
        console.error('Error fetching saved tracks:', error);
        res.status(500).json({ error: 'Error fetching saved tracks' });
    }
});

app.delete('/api/music/tracks/:trackId', authenticateJWT,async (req, res) => {
  try {
    const { trackId } = req.params;

    // Find and delete the track by its ID for the authenticated user
    const deletedTrack = await Track.findOneAndDelete({ _id: trackId, userId: req.userId });

    // Check if a track was deleted
    if (!deletedTrack) {
      return res.status(404).json({ message: 'Track not found or you do not have permission to delete this track.' });
    }

    // Successful deletion
    res.status(204).send(); // No content
  } catch (error) {
    console.error('Error deleting track:', error); // Log the error details
    res.status(500).json({ message: 'Error deleting track', error: error.message });
  }
});



app.get('/api/admin/users', authenticateJWT, async (req, res) => {
  try {
    // Find the authenticated user by ID
    const user = await User.findById(req.userId);

    // Check if the user is an admin
    // if (user.role !== 'admin') {
    //   return res.status(403).json({ message: 'Access denied. Admins only.' });
    // }

    // Find all users and select only their username and email
    const users = await User.find().select('username email');

    // Map through the users to create a list of their usernames and emails
    const userList = users.map(user => ({
      username: user.username,
      email: user.email
    }));

    // Return the list of usernames and emails
    res.status(200).json({ users: userList });
  } catch (error) {
    console.error('Error fetching user information:', error);
    res.status(500).json({ message: 'Error fetching user information' });
  }
});


// Authentication middleware
const authenticate = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  
  if (!token) {
    return res.status(403).json({ message: 'No token provided' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: 'Unauthorized' });
    }
    req.userId = decoded.id; // Attach user ID to the request
    next();
  });
};

// Route to get user songs
app.get('/api/users/:username/songs', authenticate, async (req, res) => {
  const { username } = req.params;

  try {
    // Find the user by username
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Assuming you have a relationship where User has saved songs
    const songs = await Track.find({ userId: user._id }); // Adjust based on your schema

    return res.status(200).json({ songs });
  } catch (err) {
    console.error('Error fetching user songs:', err);
    return res.status(500).json({ message: 'Internal Server Error' });
  }
});





// Other routes and server setup...
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
