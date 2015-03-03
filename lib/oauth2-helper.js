function clientInfo(client) {
  if (!client) {
    return client;
  }
  return client.id + ',' + client.name;
}

function userInfo(user) {
  if (!user) {
    return user;
  }
  return user.id + ',' + user.username + ',' + user.email;
}

function isExpired(tokenOrCode) {
  var issuedTime =
    (tokenOrCode.issuedAt && tokenOrCode.issuedAt.getTime()) || -1;
  var now = Date.now();
  var expirationTime =
    (tokenOrCode.expiredAt && tokenOrCode.expiredAt.getTime()) || -1;
  if (expirationTime === -1 && issuedTime !== -1 &&
    typeof tokenOrCode.expiresIn === 'number') {
    expirationTime = issuedTime + tokenOrCode.expiresIn * 1000;
  }
  return now > expirationTime;
}

module.exports = {
  clientInfo: clientInfo,
  userInfo: userInfo,
  isExpired: isExpired
};
