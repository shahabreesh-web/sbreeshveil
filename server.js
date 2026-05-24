// server.js - উন্নত সংস্করণ
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const dotenv = require('dotenv');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

dotenv.config();

const app = express();
app.use(cors());
app.use(helmet());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use('/api/', limiter);

mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('✅ MongoDB Connected'))
  .catch(err => { console.error('❌ MongoDB Error:', err.message); process.exit(1); });

// MODELS
const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true, minlength: 6 },
  role: { type: String, enum: ['customer', 'vendor', 'admin'], default: 'customer' },
  phone: { type: String },
  address: { type: String },
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
});

userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  const salt = await bcrypt.genSalt(12);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

userSchema.methods.matchPassword = async function(pw) {
  return await bcrypt.compare(pw, this.password);
};

userSchema.methods.getToken = function() {
  return jwt.sign({ id: this._id, role: this.role }, process.env.JWT_SECRET, { expiresIn: '30d' });
};

const User = mongoose.model('User', userSchema);

const productSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  description: { type: String, required: true },
  price: { type: Number, required: true, min: 0 },
  category: { type: String, required: true },
  image: { type: String },
  vendor: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  stock: { type: Number, default: 0, min: 0 },
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
});

const Product = mongoose.model('Product', productSchema);

const orderSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  products: [{ product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product' }, quantity: Number, price: Number }],
  totalAmount: { type: Number, required: true, min: 0 },
  status: { type: String, enum: ['pending', 'processing', 'shipped', 'delivered'], default: 'pending' },
  shippingAddress: { type: String, required: true },
  paymentStatus: { type: String, default: 'pending' },
  createdAt: { type: Date, default: Date.now }
});

const Order = mongoose.model('Order', orderSchema);

const walletSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
  balance: { type: Number, default: 0 },
  transactions: [{ amount: Number, type: String, description: String, date: { type: Date, default: Date.now } }]
});

const Wallet = mongoose.model('Wallet', walletSchema);

// MIDDLEWARE
const protect = async (req, res, next) => {
  let token;
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  }
  if (!token) return res.status(401).json({ success: false, message: 'No token' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = await User.findById(decoded.id);
    if (!req.user) return res.status(401).json({ success: false, message: 'User not found' });
    if (!req.user.isActive) return res.status(401).json({ success: false, message: 'Account deactivated' });
    next();
  } catch { res.status(401).json({ success: false, message: 'Invalid token' }); }
};

const isVendor = (req, res, next) => {
  if (req.user.role !== 'vendor' && req.user.role !== 'admin') return res.status(403).json({ success: false, message: 'Vendor only' });
  next();
};

const isAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') return res.status(403).json({ success: false, message: 'Admin only' });
  next();
};

// AUTH ROUTES
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    if (!name || !email || !password) return res.status(400).json({ success: false, message: 'Fill all fields' });
    if (password.length < 6) return res.status(400).json({ success: false, message: 'Min 6 chars' });
    if (await User.findOne({ email })) return res.status(400).json({ success: false, message: 'Email exists' });
    const user = await User.create({ name, email, password, role: role || 'customer' });
    if (role === 'vendor') await Wallet.create({ user: user._id });
    res.status(201).json({ success: true, data: { _id: user._id, name: user.name, email: user.email, role: user.role, token: user.getToken() } });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user || !(await user.matchPassword(password))) return res.status(401).json({ success: false, message: 'Invalid' });
    if (!user.isActive) return res.status(401).json({ success: false, message: 'Deactivated' });
    res.json({ success: true, data: { _id: user._id, name: user.name, email: user.email, role: user.role, token: user.getToken() } });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.get('/api/auth/profile', protect, async (req, res) => {
  res.json({ success: true, data: await User.findById(req.user._id).select('-password') });
});

app.put('/api/auth/profile', protect, async (req, res) => {
  try {
    const { name, phone, address, password } = req.body;
    const user = await User.findById(req.user._id);
    if (name) user.name = name;
    if (phone) user.phone = phone;
    if (address) user.address = address;
    if (password) user.password = password;
    await user.save();
    res.json({ success: true, data: { name: user.name, email: user.email, role: user.role } });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// PRODUCT ROUTES
app.get('/api/products', async (req, res) => {
  const { category, search } = req.query;
  const query = { isActive: true };
  if (category) query.category = category;
  if (search) query.$or = [{ name: { $regex: search, $options: 'i' } }, { description: { $regex: search, $options: 'i' } }];
  const products = await Product.find(query).populate('vendor', 'name').sort({ createdAt: -1 });
  res.json({ success: true, data: products });
});

app.get('/api/products/:id', async (req, res) => {
  const product = await Product.findById(req.params.id).populate('vendor', 'name email');
  product ? res.json({ success: true, data: product }) : res.status(404).json({ success: false, message: 'Not found' });
});

app.post('/api/products', protect, isVendor, async (req, res) => {
  try {
    const { name, description, price, category, image, stock } = req.body;
    if (!name || !description || !price || !category) return res.status(400).json({ success: false, message: 'Fill all fields' });
    const product = await Product.create({ ...req.body, vendor: req.user._id });
    res.status(201).json({ success: true, data: product });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.put('/api/products/:id', protect, isVendor, async (req, res) => {
  const p = await Product.findById(req.params.id);
  if (!p || p.vendor.toString() !== req.user._id.toString()) return res.status(404).json({ success: false, message: 'Not authorized' });
  res.json({ success: true, data: await Product.findByIdAndUpdate(req.params.id, req.body, { new: true }) });
});

app.delete('/api/products/:id', protect, isVendor, async (req, res) => {
  const p = await Product.findById(req.params.id);
  if (!p || p.vendor.toString() !== req.user._id.toString()) return res.status(404).json({ success: false, message: 'Not authorized' });
  p.isActive = false; await p.save();
  res.json({ success: true, message: 'Deleted' });
});

app.get('/api/products/vendor/my', protect, isVendor, async (req, res) => {
  res.json({ success: true, data: await Product.find({ vendor: req.user._id }) });
});

// ORDER ROUTES
app.post('/api/orders', protect, async (req, res) => {
  try {
    const { products, shippingAddress } = req.body;
    if (!products?.length || !shippingAddress) return res.status(400).json({ success: false, message: 'Fill all' });
    let total = 0, orderProducts = [];
    for (const item of products) {
      const prod = await Product.findById(item.product);
      if (prod) { total += prod.price * item.quantity; orderProducts.push({ product: prod._id, quantity: item.quantity, price: prod.price }); }
    }
    const order = await Order.create({ user: req.user._id, products: orderProducts, totalAmount: total, shippingAddress });
    res.status(201).json({ success: true, data: order });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.get('/api/orders/my', protect, async (req, res) => {
  res.json({ success: true, data: await Order.find({ user: req.user._id }).populate('products.product') });
});

app.get('/api/orders/vendor', protect, isVendor, async (req, res) => {
  const prods = await Product.find({ vendor: req.user._id });
  const orders = await Order.find({ 'products.product': { $in: prods.map(p => p._id) } }).populate('products.product').populate('user', 'name email');
  res.json({ success: true, data: orders });
});

app.put('/api/orders/:id/status', protect, isVendor, async (req, res) => {
  const order = await Order.findById(req.params.id);
  order ? res.json({ success: true, data: await Order.findByIdAndUpdate(req.params.id, req.body, { new: true }) }) : res.status(404).json({ success: false, message: 'Not found' });
});

app.get('/api/orders/admin', protect, isAdmin, async (req, res) => {
  res.json({ success: true, data: await Order.find().populate('products.product').populate('user', 'name email') });
});

// PAYMENT ROUTES
app.get('/api/payment/wallet', protect, async (req, res) => {
  let w = await Wallet.findOne({ user: req.user._id });
  if (!w) w = await Wallet.create({ user: req.user._id, balance: 0 });
  res.json({ success: true, data: w });
});

app.post('/api/payment/wallet/deposit', protect, async (req, res) => {
  try {
    let w = await Wallet.findOne({ user: req.user._id });
    if (!w) w = await Wallet.create({ user: req.user._id, balance: 0 });
    w.balance += req.body.amount;
    w.transactions.push({ amount: req.body.amount, type: 'credit', description: req.body.description || 'Deposit' });
    await w.save();
    res.json({ success: true, data: w });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/payment/pay', protect, async (req, res) => {
  const { orderId, amount } = req.body;
  const w = await Wallet.findOne({ user: req.user._id });
  if (w.balance < amount) return res.status(400).json({ success: false, message: 'Insufficient balance' });
  w.balance -= amount;
  w.transactions.push({ amount, type: 'debit', description: 'Order payment' });
  await w.save();
  const o = await Order.findById(orderId);
  if (o) { o.paymentStatus = 'paid'; await o.save(); }
  res.json({ success: true, message: 'Paid', data: w });
});

app.get('/api/payment/transactions', protect, async (req, res) => {
  const w = await Wallet.findOne({ user: req.user._id });
  res.json({ success: true, data: w.transactions });
});

// SERVER
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
