const bcrypt = require('bcrypt');
const readline = require('readline').createInterface({
  input: process.stdin,
  output: process.stdout
});

// Recommended cost factor (10-12 is good for most applications)
const saltRounds = 12;

readline.question('Enter password to hash: ', async (password) => {
  try {
    // Generate a salt and hash the password
    const hash = await bcrypt.hash(password, saltRounds);
    
    console.log('\nHashed password:');
    console.log(hash);
    
    // The hash contains everything bcrypt needs (algorithm, cost, salt, hash)
    // Format: $2b$[cost]$[22 character salt][31 character hash]
    // Example: $2b$12$sdfghjkloiuytrewqasdf.hjklytrewqasdfghjkl
    
    // Verify it works (optional demonstration)
    const isMatch = await bcrypt.compare(password, hash);
    console.log(`\nPassword verification: ${isMatch ? '✅ Success' : '❌ Failed'}`);
  } catch (err) {
    console.error('Error hashing password:', err);
  } finally {
    readline.close();
  }
});