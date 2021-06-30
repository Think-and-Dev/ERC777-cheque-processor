//SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.7.0;

// Copyright (C) 2021  Pedro Prete

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

import "./LibEIP712.sol";
import "./IERC777.sol";

// Inspired by https://github.com/dapphub/ds-dach/blob/master/src/dach.sol
contract ERC777ChequeProcessor {
    // keccak256("Transfer(address to,uint256 amount,bytes32 transactionHash,address relayer,uint256 fee,uint256 nonce,uint256 deadline)");
    bytes32 public constant TRANSFER_TYPEHASH = 0xf18ceda3f6355f78c234feba066041a50f6557bfb600201e2a71a89e2dd80433;
    bytes32 public DOMAIN_SEPARATOR;
    address public uniswapRouter;
    mapping(address => uint) public nonces;

    constructor(address _uniswapRouter) {
        uniswapRouter = _uniswapRouter;
        uint256 chainId;
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            chainId := chainid()
        }
        DOMAIN_SEPARATOR = LibEIP712.hashEIP712Domain(
            "ERC777 Cheque Processor",
            "1",
            chainId,
            address(this)
        );
    }

    function digestTransfer(
        address token,
        address owner,
        address to,
        uint256 value,
        uint256 fee,
        uint256 deadline
    ) internal returns (bytes32) {
        return LibEIP712.hashEIP712Message(
            DOMAIN_SEPARATOR,
            keccak256(
                abi.encode(
                    TRANSFER_TYPEHASH,
                    token,
                    owner,
                    value,
                    to,
                    fee,
                    nonces[owner]++,
                    deadline
                )
            )
        );
    }

    // Sell @amount dai for eth on uniswap
    function transfer(
        address token,
        address owner,
        address to,
        uint256 value,
        uint256 fee,
        uint256 deadline,
        address relayer,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public {
      require(deadline >= block.timestamp, "EXPIRED");
      require(owner != address(0) && owner == ecrecover(
            digestTransfer(
                token,
                owner,
                to,
                value,
                fee,
                deadline
            ),
            v,
            r,
            s
        ),"INVALID_SIGNATURE");
        IERC777(token).operatorSend(owner, to, value, "", "");
        IERC777(token).operatorSend(owner, relayer, fee, "", "");
    }

}
