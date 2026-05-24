const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const mongoose = require('mongoose');

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('MongoDB Connected'))
  .catch(err => { console.error('Error:', err.message); process.exit(1); });

const User = mongoose.model('User', new mongoose.Schema({
  name: String, email: String, password: String, role: { type: String, default: 'customer' }
}));

const Product = mongoose.model('Product', new mongoose.Schema({
  name: String, description: String, price: Number, category: String, 
  vendor: mongoose.Schema.Types.ObjectId, isActive: { type: Boolean, default: true }
}));

const Order = mongoose.model('Order', new mongoose.Schema({
  user: mongoose.Schema.Types.ObjectId, products: Array, totalAmount: Number, 
  status: String, shippingAddress: String
}));

const Wallet = mongoose.model('Wallet', new mongoose.Schema({
  user: mongoose.Schema.Types.ObjectId, balance: Number, transactions: Array
}));

app.get('/api/products', async (req, res) => {
  res.json({ success: true, data: await Product.find({ isActive: true }) });
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    if (await User.findOne({ email })) return res.status(400).json({ message: 'Exists' });
    const user = await User.create({ name, email, password, role });
    res.json({ success: true, data: { _id: user._id, name, email, role } });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email, password });
    if (!user) return res.status(401).json({ message: 'Invalid' });
    const jwt = require('jsonwebtoken');
    res.json({ success: true, token: jwt.sign({ id: user._id }, process.env.JWT_SECRET) });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server on ${PORT}`));
