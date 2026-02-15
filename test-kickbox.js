const Kickbox = require('kickbox');
const dotenv = require('dotenv');
dotenv.config();

async function testKickbox() {
  console.log('Testing Kickbox with:', process.env.KICKBOX_API_KEY);
  const kickbox = Kickbox.client(process.env.KICKBOX_API_KEY).kickbox();

  try {
    kickbox.verify('test@gmail.com', (err, response) => {
      if (err) {
        console.error('❌ Kickbox failed:', err);
      } else {
        console.log('✅ Kickbox success:', response.body);
      }
    });
  } catch (error) {
    console.error('❌ Kickbox error:', error.message);
  }
}

testKickbox();
