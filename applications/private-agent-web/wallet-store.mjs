export function store(key, value) {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open("dsmack-private-agent", 1);
    open.onupgradeneeded = () => open.result.createObjectStore("wallet");
    open.onerror = () => reject(open.error);
    open.onsuccess = () => {
      const db = open.result,
        tx = db.transaction(
          "wallet",
          value === undefined ? "readonly" : "readwrite",
        );
      const request = value === undefined
        ? tx.objectStore("wallet").get(key)
        : tx.objectStore("wallet").put(value, key);
      let result;
      request.onsuccess = () => {
        result = request.result;
      };
      tx.oncomplete = () => {
        db.close();
        resolve(result);
      };
      tx.onerror = () => {
        db.close();
        reject(tx.error);
      };
    };
  });
}
