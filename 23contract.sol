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

  event Sent(address msgSender, address toAddress, address otherSigner, bytes data, uint value, bytes32 hash);
  event Deposited(uint value, address from, bytes data);
  event SetSafeModeActivated(address msgSender);

  address[] public signers;
  bool public safeMode = false;

  uint constant MAX_SEQUENCE_ID_SIZE = 10;
  uint[10] recentSequenceIds;

  constructor(address[] memory allowedSigners) public {
    if (allowedSigners.length != 3) {
      revert();
    }
    signers = allowedSigners;
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

  modifier onlySigner {
    if (!isSigner(msg.sender)) {
      revert();
    }
    _;
  }

  function sendEth(uint value, uint expireTime, bytes memory data, uint sequenceId, address toAddress, bytes memory signature) public payable onlySigner {
    bytes32 hash = keccak256(abi.encodePacked("ETHER", toAddress, value, data, expireTime, sequenceId));
    address otherSigner = verifySignature(toAddress, hash, signature, expireTime, sequenceId);
    if( !toAddress.send(value)){
        revert();
    }
    emit Sent(msg.sender, toAddress, otherSigner, data, value, hash);
  }

  function sendToken(uint value, uint expireTime, uint sequenceId, address toAddress, address tokenContractAddress, bytes memory signature) public onlySigner {
    bytes32 hash = keccak256(abi.encodePacked("ERC20", toAddress, value, tokenContractAddress, expireTime, sequenceId));
    verifySignature(toAddress, hash, signature, expireTime, sequenceId);
    if(!ERC20Interface(tokenContractAddress).safeTransfer(toAddress, value)){
        revert();
    }
  }

  function verifySignature(
      address toAddress,
      bytes32 hash,
      bytes memory signature,
      uint expireTime,
      uint sequenceId
  ) private returns (address) {
    address otherSigner = recoverFromSignature(hash, signature);
    if (safeMode && !isSigner(toAddress)) {
      revert();
    }
    if (expireTime < block.timestamp) {
      revert();
    }
    insertSequenceId(sequenceId);
    if (!isSigner(otherSigner)) {
      revert();
    }
    if (otherSigner == msg.sender) {
      revert();
    }
    return otherSigner;
  }

  function setSafeMode() public onlySigner {
    safeMode = true;
    emit SetSafeModeActivated(msg.sender);
  }

  function recoverFromSignature(bytes32 hash, bytes memory signature) private pure returns (address) {
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
    return ecrecover(hash, v, r, s);
  }

  function insertSequenceId(uint sequenceId) private onlySigner {
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
}
