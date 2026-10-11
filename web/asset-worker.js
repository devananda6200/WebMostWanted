import {syncAssets} from './asset-sync.js';
self.onmessage = async ({data}) => {
  try {
    await syncAssets({...data, report: value => self.postMessage(value)});
  } catch (error) {
    self.postMessage({type: 'error', message: error.message, stack: error.stack});
  }
};
