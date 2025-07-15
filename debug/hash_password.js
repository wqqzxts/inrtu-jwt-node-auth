const bcrypt = require("bcrypt");
const readline = require("readline").createInterface({
  input: process.stdin,
  output: process.stdout,
});

const saltRounds = 12;

readline.question("Enter password to hash: ", async (password) => {
  try {
    const hash = await bcrypt.hash(password, saltRounds);

    console.log("\nHashed password:");
    console.log(hash);

    const isMatch = await bcrypt.compare(password, hash);
    console.log(`\nPassword verification: ${isMatch ? "Success" : "Failed"}`);
  } catch (err) {
    console.error("Error hashing password:", err);
  } finally {
    readline.close();
  }
});
