const { Builder, By, until } = require('selenium-webdriver');
const path = require('path');

async function startWhatsApp() {
  const driver = await new Builder().forBrowser('chrome').build();
  await driver.get('https://web.whatsapp.com');
  console.log("🔐 Scan the QR code...");
  await driver.sleep(45000); // Wait 45 sec for QR scan
  return driver;
}

async function sendMessageToOne(driver, contact, message, mediaPath = null) {
  const phone = contact.startsWith('91') ? contact : `91${contact}`;
  const url = `https://web.whatsapp.com/send?phone=${phone}&text=${encodeURIComponent(message)}`;
  console.log("→ Navigating to chat:", phone);

  await driver.get(url);
  await driver.sleep(10000);

  // Attach media if exists
  if (mediaPath) {
    try {
      console.log("📌 Waiting for clip button...");
      const clipBtn = await driver.wait(until.elementLocated(By.css('span[data-icon="clip"]')), 4500000);
      await clipBtn.click();
      await driver.sleep(1500);

      const fileInput = await driver.findElement(By.css('input[type="file"]'));
      await fileInput.sendKeys(path.resolve(mediaPath));
      await driver.sleep(8000); // Wait for media preview
    } catch (err) {
      console.error("❌ Clip or attach failed:", err);
    }
  }

  // Click send
  try {
    console.log("🚀 Trying to click send...");
    const sendBtn = await driver.wait(until.elementLocated(By.css('span[data-icon="send"]')), 450000);
    await sendBtn.click();
    console.log("✅ Sent to", phone);
    await driver.sleep(5000);
  } catch (err) {
    console.error("❌ Send failed:", err);
  }
}

async function stopWhatsApp(driver) {
  await driver.quit();
  console.log("🚑 WhatsApp closed.");
}

module.exports = { startWhatsApp, sendMessageToOne, stopWhatsApp };
