const userService = require('../services/user');

class UserController {
  async updatePassword(req, res, next) {
    try {
      const { currentPassword, newPassword } = req.body;
      const userId = req.userId;

      await userService.updatePassword(userId, currentPassword, newPassword);

      res.status(201).json({
        msg: "Password updated successfully"
      });
    } catch (error) {
      next(error);
    }
  }
}

module.exports = new UserController();