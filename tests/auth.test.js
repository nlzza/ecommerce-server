const authController = require('../controller/auth.js');
const userModel = require('../models/users');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Mock the dependencies
jest.mock('../models/users.js');
jest.mock('bcryptjs');
jest.mock('jsonwebtoken');

describe('Auth Controller', () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('isAdmin', () => {
    it('should return user role', async () => {
      const req = { body: { loggedInUserId: '12345' } };
      const res = { json: jest.fn(), status: jest.fn().mockReturnThis() };
      userModel.findById.mockResolvedValue({ userRole: 'admin' });

      await authController.isAdmin(req, res);

      expect(userModel.findById).toHaveBeenCalledWith('12345');
      expect(res.json).toHaveBeenCalledWith({ role: 'admin' });
    });

    it('should return 404 if user not found', async () => {
      const req = { body: { loggedInUserId: '12345' } };
      const res = { json: jest.fn(), status: jest.fn().mockReturnThis() };
      userModel.findById.mockResolvedValue(null);

      await authController.isAdmin(req, res);

      expect(userModel.findById).toHaveBeenCalledWith('12345');
      expect(res.status).toHaveBeenCalledWith(404);
    });
  });

  describe('allUser', () => {
    it('should return all users', async () => {
      const req = {};
      const res = { json: jest.fn(), status: jest.fn().mockReturnThis() };
      userModel.find.mockResolvedValue([{ name: 'John' }, { name: 'Jane' }]);

      await authController.allUser(req, res);

      expect(userModel.find).toHaveBeenCalledWith({});
      expect(res.json).toHaveBeenCalledWith({ users: [{ name: 'John' }, { name: 'Jane' }] });
    });

    it('should return 404 if an error occurs', async () => {
      const req = {};
      const res = { json: jest.fn(), status: jest.fn().mockReturnThis() };
      userModel.find.mockRejectedValue(new Error('Database error'));

      await authController.allUser(req, res);

      expect(userModel.find).toHaveBeenCalledWith({});
      expect(res.status).toHaveBeenCalledWith(404);
    });
  });

  describe('postSignup', () => {
    it('should return error if required fields are missing', async () => {
      const req = { body: {} };
      const res = { json: jest.fn() };

      await authController.postSignup(req, res);

      expect(res.json).toHaveBeenCalledWith({
        error: {
          name: 'Filed must not be empty',
          email: 'Filed must not be empty',
          password: 'Filed must not be empty',
          cPassword: 'Filed must not be empty',
        },
      });
    });

    // Additional tests for other scenarios...
  });

  describe('postSignin', () => {
    it('should return error if email or password is missing', async () => {
      const req = { body: {} };
      const res = { json: jest.fn() };

      await authController.postSignin(req, res);

      expect(res.json).toHaveBeenCalledWith({ error: 'Fields must not be empty' });
    });

    it('should return error if user not found', async () => {
      const req = { body: { email: 'test@example.com', password: 'password' } };
      const res = { json: jest.fn() };
      userModel.findOne.mockResolvedValue(null);

      await authController.postSignin(req, res);

      expect(userModel.findOne).toHaveBeenCalledWith({ email: 'test@example.com' });
      expect(res.json).toHaveBeenCalledWith({ error: 'Invalid email or password' });
    });

    it('should return token and user if login successful', async () => {
      const req = { body: { email: 'test@example.com', password: 'password' } };
      const res = { json: jest.fn() };
      const user = { _id: '12345', email: 'test@example.com', password: 'hashedPassword', userRole: 'user' };
      userModel.findOne.mockResolvedValue(user);
      bcrypt.compare.mockResolvedValue(true);
      jwt.sign.mockReturnValue('token');
      jwt.verify.mockReturnValue({ _id: '12345', role: 'user' });

      await authController.postSignin(req, res);

      expect(userModel.findOne).toHaveBeenCalledWith({ email: 'test@example.com' });
      expect(bcrypt.compare).toHaveBeenCalledWith('password', 'hashedPassword');
      expect(jwt.sign).toHaveBeenCalledWith({ _id: '12345', role: 'user' }, 'SecretKey');
      expect(jwt.verify).toHaveBeenCalledWith('token', 'SecretKey');
      expect(res.json).toHaveBeenCalledWith({
        token: 'token',
        user: { _id: '12345', role: 'user' },
      });
    });

    // Additional tests for other scenarios...
  });
});
