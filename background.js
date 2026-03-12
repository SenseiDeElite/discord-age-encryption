// background.js — Discord Age Encryption service worker
//
// Re-sends the age identity string to a Discord tab when it finishes loading,
// so the content script is unlocked immediately without the user reopening the popup.

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status !== 'complete') return;
  if (!tab.url?.startsWith('https://discord.com/')) return;

  chrome.storage.session.get(['age_unlocked', 'age_identity'], (data) => {
    if (!data.age_unlocked || !data.age_identity) return;
    setTimeout(() => {
      chrome.tabs.sendMessage(tabId, {
        type: 'UNLOCK',
        identity: data.age_identity
      }, () => {
        void chrome.runtime.lastError;
      });
    }, 800);
  });
});
