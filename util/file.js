const fs = require('fs');

exports.deleteFile = filepath => {
  fs.unlink(filepath, err => {
    if (err) {
      throw new Error(err);
    }
  });
};
