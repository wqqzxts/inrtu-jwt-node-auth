// for bcrypt
function isHash(str) {        
    const bcryptRegex = /^\$2[aby]\$\d{2}\$[./0-9A-Za-z]{53}$/;
    return bcryptRegex.test(str);
};

module.exports = isHash;