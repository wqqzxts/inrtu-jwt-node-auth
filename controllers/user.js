const userService = require('../services/user');

class UserController {
  async updatePassword(req, res, next) {
    try {
      const { current_password, new_password } = req.body;
      const userId = req.userId;

      await userService.updatePassword(userId, current_password, new_password);

      res.status(201).json({
        msg: "Password updated successfully"
      });
    } catch (error) {
      next(error);
    }
  }
}

module.exports = new UserController();