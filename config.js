module.exports = {
  ENV: process.env.NODE_ENV || 'development',
  PORT: process.env.PORT || 3000,
  URL: process.env.BASE_URL || 'http://localhost:3000/',
  MONGODB_URI:
    process.env.MONGODB_URI ||
    'mongodb://abc123!:abc123!@ds131384.mlab.com:31384/customer_api',
  JWT_SECRET: process.env.JWT_SECRET || 'secret1'
};
