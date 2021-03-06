pragma solidity ^0.4.24;

library ERC20SafeTransfer {
    function safeTransfer(address _tokenAddress, address _to, uint256 _value) internal returns (bool success) {
        bytes memory hash = abi.encodeWithSignature("transfer(address,uint256)", _to, _value);
        uint msgSize = hash.length;

        assembly {
            mstore(0x00, 0xff)

            if iszero(call(gas(), _tokenAddress, 0, add(hash, 0x20), msgSize, 0x00, 0x20)) { revert(0, 0) }

            switch mload(0x00)
            case 0xff {
                success := 1
            }
            case 0x01 {
                success := 1
            }
            case 0x00 {
                success := 0
            }
            default {
                revert(0, 0)
            }
        }
    }
}

interface ERC20Interface {
  function transfer (address _to, uint256 _value) external returns (bool success);
  function balanceOf(address _owner) external view returns (uint256 balance);
}

contract ethMultiSig {
  using ERC20SafeTransfer for ERC20Interface;
  event Sent(address msgSender, address toAddress, address[] otherSigners, bytes data, uint value, bytes32 hash);
  event Deposited(uint value, address from, bytes data);
  event SetSafeModeActivated(address msgSender);

  address[] public signers;
  address[] public senders;
  uint countSigners;
  uint minNeedSigners;
  bool public safeMode = false;

  uint constant MAX_SEQUENCE_ID_SIZE = 10;
  uint[10] recentSequenceIds;

  constructor(address[] memory allowedSigners,address[] memory extraSenders,uint m, uint n) public {
    if (allowedSigners.length != n) {
      revert();
    }
    signers = allowedSigners;
    for (uint i = 0; i < signers.length; i++) {
        senders.push(signers[i]);
    }
    for (uint j = 0; j < extraSenders.length; j++) {
        senders.push(extraSenders[j]);
    }
    countSigners = n;
    minNeedSigners = m;
  }

  function() external payable {
    if (msg.value > 0) {
      emit Deposited(msg.value, msg.sender, msg.data);
    }
  }

  function isSigner(address signer) public view returns (bool) {
    for (uint i = 0; i < signers.length; i++) {
      if (signers[i] == signer) {
        return true;
      }
    }
    return false;
  }

  function isSender(address sender) public view returns (bool) {
    for (uint i = 0; i < senders.length; i++) {
      if (senders[i] == sender) {
        return true;
      }
    }
    return false;
  }

   modifier onlySender {
    if (!isSender(msg.sender)) {
      revert();
    }
    _;
  }

  function sendEth(uint value, uint expireTime, bytes memory data, uint sequenceId, address toAddress, bytes memory signatures) public payable onlySender {
    bytes32 hash = keccak256(abi.encodePacked("ETHER", toAddress, value, data, expireTime, sequenceId));
    address [] memory otherSigners = verifySignature(toAddress, hash, signatures, expireTime, sequenceId);
    if( !toAddress.send(value)){
        revert();
    }
    emit Sent(msg.sender, toAddress, otherSigners, data, value, hash);
  }

  function sendToken(uint value, uint expireTime, uint sequenceId, address toAddress, address tokenContractAddress, bytes memory signatures) public onlySender {
    bytes32 hash = keccak256(abi.encodePacked("ERC20", toAddress, value, tokenContractAddress, expireTime, sequenceId));
    verifySignature(toAddress, hash, signatures, expireTime, sequenceId);
    if(!ERC20Interface(tokenContractAddress).safeTransfer(toAddress, value)){
        revert();
    }
  }

  function verifySignature(address toAddress, bytes32 hash, bytes memory signatures, uint expireTime, uint sequenceId) private returns (address [] memory) {
    if (safeMode && !isSigner(toAddress)) {
     revert();
    }
    if (expireTime < block.timestamp) {
     revert();
    }
    insertSequenceId(sequenceId);
    uint signatureLength = 65;
    if( signatures.length != minNeedSigners * signatureLength ){
        revert();
    }
    address [] memory otherSigners = new address[](minNeedSigners);
    for (uint i = 0; i < minNeedSigners ; i++) {
      bytes memory curSignatures = new bytes(signatureLength);
      for( uint j = 0 ; j < 65  ; j++){
          curSignatures[j] = signatures[ i*signatureLength + j];
      }
      address otherSigner = recoverFromSignature(hash, curSignatures);
      if (!isSigner(otherSigner)) {
        revert();
      }
      if( isInArray(otherSigner, otherSigners)){
          revert();
      }
       otherSigners[i] = otherSigner;
    }
    return otherSigners;
  }

  function setSafeMode() public onlySender {
    safeMode = true;
    emit SetSafeModeActivated(msg.sender);
  }

  function recoverFromSignature(bytes32 operationHash, bytes memory signature) private pure returns (address) {
    if (signature.length != 65) {
      revert();
    }
    bytes32 r;
    bytes32 s;
    uint8 v;
    assembly {
      r := mload(add(signature, 32))
      s := mload(add(signature, 64))
      v := and(mload(add(signature, 65)), 255)
    }
    if (v < 27) {
      v += 27;
    }
    return ecrecover(operationHash, v, r, s);
  }

  function insertSequenceId(uint sequenceId) private onlySender {
    uint minIndex = 0;
    for (uint i = 0; i < MAX_SEQUENCE_ID_SIZE; i++) {
      if (recentSequenceIds[i] == sequenceId) {
        revert();
      }
      if (recentSequenceIds[i] < recentSequenceIds[minIndex]) {
        minIndex = i;
      }
    }
    if (sequenceId < recentSequenceIds[minIndex]) {
      revert();
    }
    if (sequenceId > (recentSequenceIds[minIndex] + 10000)) {
     revert();
    }
    recentSequenceIds[minIndex] = sequenceId;
  }

  function getNextSequenceId() public view returns (uint) {
    uint maxSequenceId = 0;
    for (uint i = 0; i < MAX_SEQUENCE_ID_SIZE; i++) {
      if (recentSequenceIds[i] > maxSequenceId) {
        maxSequenceId = recentSequenceIds[i];
      }
    }
    return maxSequenceId + 1;
  }

  function isInArray(address item, address [] memory items) private pure returns (bool) {
    for (uint i = 0; i < items.length; i++) {
      if (items[i] == item) {
        return true;
      }
    }
    return false;
  }
}
