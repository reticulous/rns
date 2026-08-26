/*
 * Copyright (c) 2023 Chad Attermann
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 */

#include "Identity.h"

#include "Reticulum.h"
#include "Transport.h"
#include "Packet.h"
#include "Log.h"
#include "Utilities/OS.h"
#include "Cryptography/Ed25519.h"
#include "Cryptography/X25519.h"
#include "Cryptography/HKDF.h"
#include "Cryptography/Token.h"
#include "Cryptography/Random.h"
#include "Directory.h"

#include <algorithm>
#include <string.h>

using namespace RNS;
using namespace RNS::Type::Identity;
using namespace RNS::Cryptography;
using namespace RNS::Utilities;

Identity::Identity(bool create_keys /*= true*/) : _object(new Object()) {
	if (create_keys) {
		createKeys();
	}
	MEMF("Identity object created, this: %p, data: %p", (void*)this, (void*)_object.get());
}

void Identity::createKeys() {
	assert(_object);

	// CRYPTO: create encryption private keys
	_object->_prv           = Cryptography::X25519PrivateKey::generate();
	_object->_prv_bytes     = _object->_prv->private_bytes();
	//TRACEF("Identity::createKeys: prv bytes:     %s", _object->_prv_bytes.toHex().c_str());

	// CRYPTO: create signature private keys
	_object->_sig_prv       = Cryptography::Ed25519PrivateKey::generate();
	_object->_sig_prv_bytes = _object->_sig_prv->private_bytes();
	//TRACEF("Identity::createKeys: sig prv bytes: %s", _object->_sig_prv_bytes.toHex().c_str());

	// CRYPTO: create encryption public keys
	_object->_pub           = _object->_prv->public_key();
	_object->_pub_bytes     = _object->_pub->public_bytes();
	//TRACEF("Identity::createKeys: pub bytes:     %s", _object->_pub_bytes.toHex().c_str());

	// CRYPTO: create signature public keys
	_object->_sig_pub       = _object->_sig_prv->public_key();
	_object->_sig_pub_bytes = _object->_sig_pub->public_bytes();
	//TRACEF("Identity::createKeys: sig pub bytes: %s", _object->_sig_pub_bytes.toHex().c_str());

	update_hashes();

	VERBOSEF("Identity keys created for %s", _object->_hash.toHex().c_str());
}

/*
Load a private key into the instance.

:param prv_bytes: The private key as *bytes*.
:returns: True if the key was loaded, otherwise False.
*/
bool Identity::load_private_key(const Bytes& prv_bytes) {
	assert(_object);

	try {

		//p self.prv_bytes     = prv_bytes[:Identity.KEYSIZE//8//2]
		_object->_prv_bytes     = prv_bytes.left(Type::Identity::KEYSIZE/8/2);
		_object->_prv           = X25519PrivateKey::from_private_bytes(_object->_prv_bytes);
		//TRACEF("Identity::load_private_key: prv bytes:     %s", _object->_prv_bytes.toHex().c_str());

		//p self.sig_prv_bytes = prv_bytes[Identity.KEYSIZE//8//2:]
		_object->_sig_prv_bytes = prv_bytes.mid(Type::Identity::KEYSIZE/8/2);
		_object->_sig_prv       = Ed25519PrivateKey::from_private_bytes(_object->_sig_prv_bytes);
		//TRACEF("Identity::load_private_key: sig prv bytes: %s", _object->_sig_prv_bytes.toHex().c_str());

		_object->_pub           = _object->_prv->public_key();
		_object->_pub_bytes     = _object->_pub->public_bytes();
		//TRACEF("Identity::load_private_key: pub bytes:     %s", _object->_pub_bytes.toHex().c_str());

		_object->_sig_pub       = _object->_sig_prv->public_key();
		_object->_sig_pub_bytes = _object->_sig_pub->public_bytes();
		//TRACEF("Identity::load_private_key: sig pub bytes: %s", _object->_sig_pub_bytes.toHex().c_str());

		update_hashes();

		return true;
	}
	catch (const std::exception& e) {
		//p raise e
		ERROR("Failed to load identity key");
		ERRORF("The contained exception was: %s", e.what());
		return false;
	}
}

/*
Load a public key into the instance.

:param pub_bytes: The public key as *bytes*.
:returns: True if the key was loaded, otherwise False.
*/
void Identity::load_public_key(const Bytes& pub_bytes) {
	assert(_object);

	try {

		//_pub_bytes     = pub_bytes[:Identity.KEYSIZE//8//2]
		_object->_pub_bytes     = pub_bytes.left(Type::Identity::KEYSIZE/8/2);
		//TRACEF("Identity::load_public_key: pub bytes:     ", _object->_pub_bytes.toHex().c_str());

		//_sig_pub_bytes = pub_bytes[Identity.KEYSIZE//8//2:]
		_object->_sig_pub_bytes = pub_bytes.mid(Type::Identity::KEYSIZE/8/2);
		//TRACEF("Identity::load_public_key: sig pub bytes: ", _object->_sig_pub_bytes.toHex().c_str());

		_object->_pub           = X25519PublicKey::from_public_bytes(_object->_pub_bytes);
		_object->_sig_pub       = Ed25519PublicKey::from_public_bytes(_object->_sig_pub_bytes);

		update_hashes();
	}
	catch (const std::exception& e) {
		ERRORF("Error while loading public key, the contained exception was: %s", e.what());
	}
}

bool Identity::load(const char* path) {
	TRACE("Reading identity key from storage...");
#if defined(RNS_USE_FS)
	try {
		Bytes prv_bytes;
		if (OS::read_file(path, prv_bytes) > 0) {
			return load_private_key(prv_bytes);
		}
		else {
			return false;
		}
	}
	catch (const std::exception& e) {
		ERRORF("Error while loading identity from %s", path);
		ERRORF("The contained exception was: %s", e.what());
	}
#endif
	return false;
}

/*
Saves the identity to a file. This will write the private key to disk,
and anyone with access to this file will be able to decrypt all
communication for the identity. Be very careful with this method.

:param path: The full path specifying where to save the identity.
:returns: True if the file was saved, otherwise False.
*/
bool Identity::to_file(const char* path) {
	TRACE("Writing identity key to storage...");
#if defined(RNS_USE_FS)
	try {
		return (OS::write_file(path, get_private_key()) == get_private_key().size());
	}
	catch (const std::exception& e) {
		ERRORF("Error while saving identity to %s", path);
		ERRORF("The contained exception was: %s", e.what());
	}
#endif
	return false;
}


/*
Create a new :ref:`RNS.Identity<api-identity>` instance from a file.
Can be used to load previously created and saved identities into Reticulum.

:param path: The full path to the saved :ref:`RNS.Identity<api-identity>` data
:returns: A :ref:`RNS.Identity<api-identity>` instance, or *None* if the loaded data was invalid.
*/
/*static*/ const Identity Identity::from_file(const char* path) {
	Identity identity(false);
	if (identity.load(path)) {
		return identity;
	}
	return {Type::NONE};
}

/*
Recall identity for a destination hash.

:param destination_hash: Destination hash as *bytes*.
:returns: An :ref:`RNS.Identity<api-identity>` instance that can be used to create an outgoing :ref:`RNS.Destination<api-destination>`, or *None* if the destination is unknown.
*/
/*static*/ Identity Identity::recall(const Bytes& destination_hash) {
	TRACE("Identity::recall...");
	if (destination_hash.size() == Type::Reticulum::TRUNCATED_HASHLENGTH/8) {
		uint8_t public_key[RDIR_PUBKEY_LEN];
		if (rdirPeekPubkey(destination_hash.data(), public_key)) {
			TRACEF("Identity::recall: Found directory entry for destination %s", destination_hash.toHex().c_str());
			Identity identity(false);
			identity.load_public_key(Bytes(public_key, sizeof(public_key)));
			/* app_data is not a directory field. A caller that needs it asks
			 * recall_app_data(), which answers only while the raw announce is
			 * still retained. */
			identity.app_data({Bytes::NONE});
			return identity;
		}
	}
	TRACEF("Identity::recall: No directory entry for destination %s, performing destination lookup...", destination_hash.toHex().c_str());
	Destination registered_destination(Transport::find_destination_from_hash(destination_hash));
	if (registered_destination) {
		TRACEF("Identity::recall: Found destination %s", destination_hash.toHex().c_str());
		Identity identity(false);
		identity.load_public_key(registered_destination.identity().get_public_key());
		identity.app_data({Bytes::NONE});
		return identity;
	}
	TRACEF("Identity::recall: Unable to find destination %s", destination_hash.toHex().c_str());
	return {Type::NONE};
}

/*
Recall last heard app_data for a destination hash.

:param destination_hash: Destination hash as *bytes*.
:returns: *Bytes* containing app_data, or *None* if the destination is unknown or its announce is no longer retained.
*/
/*static*/ Bytes Identity::recall_app_data(const Bytes& destination_hash) {
	TRACE("Identity::recall_app_data...");
	if (destination_hash.size() != Type::Reticulum::TRUNCATED_HASHLENGTH/8) return {Bytes::NONE};

	/* The announce's app_data sits behind its fixed prefix, so this is a slice
	 * of the retained raw announce rather than a stored copy. */
	uint8_t raw[Type::Reticulum::MTU];
	size_t n = rdirCopyBlob(destination_hash.data(), raw, sizeof(raw));
	if (n == 0) {
		TRACEF("Identity::recall_app_data: No retained announce for destination %s", destination_hash.toHex().c_str());
		return {Bytes::NONE};
	}
	Packet announce(Bytes(raw, n));
	if (!announce.unpack()) return {Bytes::NONE};
	const size_t prefix = announce_app_data_offset(announce);
	if (announce.data().size() <= prefix) return {Bytes::NONE};
	return announce.data().mid(prefix);
}

/*static*/ Bytes Identity::announce_ratchet(const Packet& packet) {
	if (packet.context_flag() != Type::Packet::FLAG_SET) return {Bytes::NONE};
	const size_t off = KEYSIZE/8 + NAME_HASH_LENGTH/8 + RANDOM_HASH_LENGTH/8;
	if (packet.data().size() < off + RATCHETSIZE/8 + SIGLENGTH/8) return {Bytes::NONE};
	return packet.data().mid(off, RATCHETSIZE/8);
}

/*static*/ size_t Identity::announce_app_data_offset(const Packet& packet) {
	size_t off = KEYSIZE/8 + NAME_HASH_LENGTH/8 + RANDOM_HASH_LENGTH/8 + SIGLENGTH/8;
	if (packet.context_flag() == Type::Packet::FLAG_SET) off += RATCHETSIZE/8;
	return off;
}

/*
Recall the ratchet a destination last announced.

:param destination_hash: Destination hash as *bytes*.
:returns: 32-byte X25519 public ratchet, or empty.
*/
/*static*/ Bytes Identity::get_ratchet(const Bytes& destination_hash) {
	if (destination_hash.size() != Type::Reticulum::TRUNCATED_HASHLENGTH/8) return {Bytes::NONE};

	/* The ratchet is not a directory field: it is read back out of the
	 * retained announce, exactly as recall_app_data reads app_data. That ties
	 * a peer's ratchet to the announce it arrived in — one lifetime, one
	 * eviction order, nothing to expire separately — and costs an unpack on
	 * the paths that need it. Only SINGLE-destination sends land here (a Link
	 * carries its own ephemeral secrecy), so that is once per opportunistic
	 * packet, not once per packet of a transfer. */
	rdir_entry_t known;
	if (!rdirPeekEntry(destination_hash.data(), &known)) return {Bytes::NONE};
	uint32_t now = (uint32_t)OS::time();
	if (now > known.last_heard && now - known.last_heard > RATCHET_EXPIRY) {
		TRACEF("Identity::get_ratchet: announce for %s is older than the ratchet expiry", destination_hash.toHex().c_str());
		return {Bytes::NONE};
	}

	uint8_t raw[Type::Reticulum::MTU];
	size_t n = rdirCopyBlob(destination_hash.data(), raw, sizeof(raw));
	if (n == 0) return {Bytes::NONE};
	Packet announce(Bytes(raw, n));
	if (!announce.unpack()) return {Bytes::NONE};
	return announce_ratchet(announce);
}

/*static*/ bool Identity::validate_announce(const Packet& packet) {
	try {
		if (packet.packet_type() == Type::Packet::ANNOUNCE) {
			Bytes destination_hash = packet.destination_hash();
			//TRACEF("Identity::validate_announce: destination_hash: %s", packet.destination_hash().toHex().c_str());
			/* A set context flag marks a RATCHETED announce: a 32-byte
			 * ratchet key sits between the random hash and the signature, and
			 * it is part of the signed data. Upstream announces ratchets by
			 * default on LXMF delivery destinations, so both layouts arrive
			 * routinely. The ratchet stays in the announce we retain; senders
			 * read it back with Identity::get_ratchet. */
			const bool   ratcheted = packet.context_flag() == Type::Packet::FLAG_SET;
			const size_t KS = KEYSIZE/8, NH = NAME_HASH_LENGTH/8, RH = RANDOM_HASH_LENGTH/8;
			Bytes ratchet = announce_ratchet(packet);
			if (ratcheted && !ratchet) {
				DEBUG("Identity::validate_announce: ratcheted announce too short to hold its ratchet, rejected");
				return false;
			}
			Bytes public_key  = packet.data().left(KS);
			Bytes name_hash   = packet.data().mid(KS, NH);
			Bytes random_hash = packet.data().mid(KS + NH, RH);
			const size_t app_off = announce_app_data_offset(packet);
			Bytes signature = packet.data().mid(app_off - SIGLENGTH/8, SIGLENGTH/8);
			Bytes app_data;
			if (packet.data().size() > app_off) {
				app_data = packet.data().mid(app_off);
			}
			//TRACEF("Identity::validate_announce: app_data:         %s", app_data.toHex().c_str());

			Bytes signed_data;
			signed_data << packet.destination_hash() << public_key << name_hash
			            << random_hash + ratchet + app_data;
			//TRACEF("Identity::validate_announce: signed_data:      %s", signed_data.toHex().c_str());

			Identity announced_identity(false);
			announced_identity.load_public_key(public_key);

			if (announced_identity.pub() && announced_identity.validate(signature, signed_data)) {
				Bytes hash_material = name_hash << announced_identity.hash();
				Bytes expected_hash = full_hash(hash_material).left(Type::Reticulum::TRUNCATED_HASHLENGTH/8);
				//TRACEF("Identity::validate_announce: destination_hash: %s", packet.destination_hash().toHex().c_str());
				//TRACEF("Identity::validate_announce: expected_hash:    %s", expected_hash.toHex().c_str());

				if (packet.destination_hash() == expected_hash) {
					// Check if we already have a public key for this destination
					// and make sure the public key is not different.
					/* rdirPeekEntry, not rdirPeekPubkey: this probe runs on every
					 * announce and a first-time destination is the normal case,
					 * so counting it as a recall miss would drown the counter
					 * that exists to show consumers asking for keys we don't
					 * hold. */
					rdir_entry_t known;
					if (rdirPeekEntry(packet.destination_hash().data(), &known) && known.has_pubkey &&
					    memcmp(known.pubkey, public_key.data(), RDIR_PUBKEY_LEN) != 0) {
						// In reality, this should never occur, but in the odd case
						// that someone manages a hash collision, we reject the announce.
						CRITICAL("Received announce with valid signature and destination hash, but announced public key does not match already known public key.");
						CRITICAL("This may indicate an attempt to modify network paths, or a random hash collision. The announce was rejected.");
						return false;
					}

					/* Nothing is stored here. Validation says the announce is
					 * genuine; what to keep about it — and at which depth — is
					 * the retention decision in Transport::inbound, which owns
					 * the one record both layers share. */

					std::string signal_str;
// TODO
/*
					if packet.rssi != None or packet.snr != None:
						signal_str = " ["
						if packet.rssi != None:
							signal_str += "RSSI "+str(packet.rssi)+"dBm"
							if packet.snr != None:
								signal_str += ", "
						if packet.snr != None:
							signal_str += "SNR "+str(packet.snr)+"dB"
						signal_str += "]"
					else:
						signal_str = ""
*/

					if (packet.transport_id()) {
						TRACEF("Valid announce for %s %d hops away, received via %s on %s%s", packet.destination_hash().toHex().c_str(), packet.hops(), packet.transport_id().toHex().c_str(), packet.receiving_interface().toString().c_str(), signal_str.c_str());
					}
					else {
						TRACEF("Valid announce for %s %d hops away, received on %s%s", packet.destination_hash().toHex().c_str(), packet.hops(), packet.receiving_interface().toString().c_str(), signal_str.c_str());
					}

					return true;
				}
				else {
					DEBUGF("Received invalid announce for %s: Destination mismatch.", packet.destination_hash().toHex().c_str());
					/* The signature verified, so every field is exactly as the
					 * origin signed it — the disagreement is in the derivation.
					 * Print both sides so a capture names the culprit. */
					/* NB operator<< mutated name_hash into hash_material above;
					 * slice the original 10 bytes back out for the print. */
					DEBUGF("  expected %s = H(name_hash %s + identity %s), ctx_flag=%d data=%uB",
					       expected_hash.toHex().c_str(),
					       hash_material.left(NAME_HASH_LENGTH/8).toHex().c_str(),
					       announced_identity.hash().toHex().c_str(),
					       (int)packet.context_flag(),
					       (unsigned)packet.data().size());
					return false;
				}
			}
			else {
				DEBUGF("Received invalid announce for %s: Invalid signature.", packet.destination_hash().toHex().c_str());
				//p del announced_identity
				return false;
			}
		}
	}
	catch (const std::exception& e) {
		ERRORF("Error occurred while validating announce. The contained exception was: %s", e.what());
		return false;
	}
	return false;
}

/*static*/ void Identity::persist_data() {
	/* Nothing of Identity's own is durable: what a node knows about other
	 * destinations lives in the directory image, which the embedder writes. */
}

/*static*/ void Identity::exit_handler() {
	persist_data();
}

/*
Encrypts information for the identity.

:param plaintext: The plaintext to be encrypted as *bytes*.
:returns: Ciphertext token as *bytes*.
:raises: *KeyError* if the instance does not hold a public key.
*/
const Bytes Identity::encrypt(const Bytes& plaintext, const Bytes& ratchet /*= {Bytes::NONE}*/) const {
	assert(_object);
	TRACE("Identity::encrypt: encrypting data...");
	if (!_object->_pub) {
		throw std::runtime_error("Encryption failed because identity does not hold a public key");
	}
	Cryptography::X25519PrivateKey::Ptr ephemeral_key = Cryptography::X25519PrivateKey::generate();
	Bytes ephemeral_pub_bytes = ephemeral_key->public_key()->public_bytes();
	TRACEF("Identity::encrypt: ephemeral public key: %s", ephemeral_pub_bytes.toHex().c_str());

	// CRYPTO: create shared key for key exchange using the destination's
	// ratchet when one was supplied, else its long-term public key. The salt
	// stays the identity hash either way, so the receiver derives the same
	// key from whichever private half opens the token.
	//shared_key = ephemeral_key.exchange(self.pub)
	const bool ratcheted = (ratchet.size() == RATCHETSIZE/8);
	if (ratcheted) {
		/* Debug rather than trace: one line per opportunistic packet or
		 * store-and-forward envelope, and the only evidence at run time that a
		 * send got forward secrecy rather than falling back to the identity
		 * key. Link traffic never reaches here. */
		DEBUGF("Identity::encrypt: encrypting to ratchet %s", ratchet_id(ratchet).toHex().c_str());
	}
	Bytes shared_key = ephemeral_key->exchange(ratcheted ? ratchet : _object->_pub_bytes);
	TRACEF("Identity::encrypt: shared key:           %s", shared_key.toHex().c_str());

	Bytes derived_key = Cryptography::hkdf(
		DERIVED_KEY_LENGTH,
		shared_key,
		get_salt(),
		get_context()
	);
	TRACEF("Identity::encrypt: derived key:          %s", derived_key.toHex().c_str());

	Cryptography::Token token(derived_key);
	TRACEF("Identity::encrypt: Token encrypting data of length %lu", plaintext.size());
	TRACEF("Identity::encrypt: plaintext:  %s", plaintext.toHex().c_str());
	Bytes ciphertext = token.encrypt(plaintext);
	TRACEF("Identity::encrypt: ciphertext: %s", ciphertext.toHex().c_str());

	return ephemeral_pub_bytes + ciphertext;
}


/*
Decrypts information for the identity.

:param ciphertext: The ciphertext to be decrypted as *bytes*.
:returns: Plaintext as *bytes*, or *None* if decryption fails.
:raises: *KeyError* if the instance does not hold a private key.
*/
const Bytes Identity::decrypt(const Bytes& ciphertext_token, const std::vector<Bytes>& ratchets /*= {}*/) const {
	assert(_object);
	TRACE("Identity::decrypt: decrypting data...");
	if (!_object->_prv) {
		throw std::runtime_error("Decryption failed because identity does not hold a private key");
	}
	if (ciphertext_token.size() <= Type::Identity::KEYSIZE/8/2) {
		INFOF("Decryption failed because the token size %lu was invalid.", ciphertext_token.size());
		return {Bytes::NONE};
	}
	Bytes plaintext;
	try {
		//peer_pub_bytes = ciphertext_token[:Identity.KEYSIZE//8//2]
		Bytes peer_pub_bytes = ciphertext_token.left(Type::Identity::KEYSIZE/8/2);
		//peer_pub = X25519PublicKey.from_public_bytes(peer_pub_bytes)
		//Cryptography::X25519PublicKey::Ptr peer_pub = Cryptography::X25519PublicKey::from_public_bytes(peer_pub_bytes);
		TRACEF("Identity::decrypt: peer public key:      %s", peer_pub_bytes.toHex().c_str());

		/* A sender that heard one of our ratchets encrypted to it, and the
		 * token says nothing about which: try each ratchet private, newest
		 * first, and fall through to the identity key for senders that heard
		 * no ratchet (or heard a rotated-out one). Every attempt is a full
		 * ECDH + HKDF + token open, so the retained-ratchet count is the
		 * ceiling on what a bad token costs us. */
		for (const Bytes& ratchet_prv : ratchets) {
			if (ratchet_prv.size() != RATCHETSIZE/8) continue;
			try {
				Bytes ratchet_shared = Cryptography::X25519PrivateKey::from_private_bytes(ratchet_prv)
				                       ->exchange(peer_pub_bytes);
				Cryptography::Token ratchet_token(Cryptography::hkdf(
					DERIVED_KEY_LENGTH, ratchet_shared, get_salt(), get_context()));
				Bytes opened = ratchet_token.decrypt(ciphertext_token.mid(Type::Identity::KEYSIZE/8/2));
				if (opened) {
					DEBUGF("Identity::decrypt: opened with ratchet %s",
					       ratchet_id(ratchet_public_bytes(ratchet_prv)).toHex().c_str());
					return opened;
				}
			}
			catch (const std::exception&) {
				// Not this ratchet — an authentication failure is the normal
				// outcome for every ratchet but the one that was used.
			}
		}

		// CRYPTO: create shared key for key exchange using peer public key
		//shared_key = _object->_prv->exchange(peer_pub);
		Bytes shared_key = _object->_prv->exchange(peer_pub_bytes);
		TRACEF("Identity::decrypt: shared key:           %s", shared_key.toHex().c_str());

		Bytes derived_key = Cryptography::hkdf(
			DERIVED_KEY_LENGTH,
			shared_key,
			get_salt(),
			get_context()
		);
		TRACEF("Identity::decrypt: derived key:          %s", derived_key.toHex().c_str());

		Cryptography::Token token(derived_key);
		//ciphertext = ciphertext_token[Identity.KEYSIZE//8//2:]
		Bytes ciphertext(ciphertext_token.mid(Type::Identity::KEYSIZE/8/2));
		TRACEF("Identity::decrypt: Token decrypting data of length %lu", ciphertext.size());
		TRACEF("Identity::decrypt: ciphertext: %s", ciphertext.toHex().c_str());
		plaintext = token.decrypt(ciphertext);
		TRACEF("Identity::decrypt: plaintext:  %s", plaintext.toHex().c_str());
		//TRACEF("Identity::decrypt: Token decrypted data of length %lu", plaintext.size());
	}
	catch (const std::exception& e) {
		WARNINGF("Decryption by %s failed: %s", toString().c_str(), e.what());
	}
		
	return plaintext;
}

/*
Signs information by the identity.

:param message: The message to be signed as *bytes*.
:returns: Signature as *bytes*.
:raises: *KeyError* if the instance does not hold a private key.
*/
const Bytes Identity::sign(const Bytes& message) const {
	assert(_object);
	if (!_object->_sig_prv) {
		throw std::runtime_error("Signing failed because identity does not hold a private key");
	}
	try {
		return _object->_sig_prv->sign(message);
	}
	catch (const std::exception& e) {
		ERRORF("The identity %s could not sign the requested message. The contained exception was: %s", toString().c_str(), e.what());
		throw e;
	}
}

/*
Validates the signature of a signed message.

:param signature: The signature to be validated as *bytes*.
:param message: The message to be validated as *bytes*.
:returns: True if the signature is valid, otherwise False.
:raises: *KeyError* if the instance does not hold a public key.
*/
bool Identity::validate(const Bytes& signature, const Bytes& message) const {
	assert(_object);
	if (_object->_pub) {
		try {
			TRACEF("Identity::validate: Attempting to verify signature: %s and message: %s", signature.toHex().c_str(), message.toHex().c_str());
			/* verify() REPORTS BY RETURN VALUE and never throws — the
			 * Python original raised on a bad signature, and porting that
			 * shape while ignoring the boolean made every signature pass. */
			return _object->_sig_pub->verify(signature, message);
		}
		catch (const std::exception& e) {
			return false;
		}
	}
	else {
		throw std::runtime_error("Signature validation failed because identity does not hold a public key");
	}
}

void Identity::prove(const Packet& packet, const Destination& destination /*= {Type::NONE}*/, bool report_signal /*= false*/) const {
	assert(_object);
	Bytes signature(sign(packet.packet_hash()));
	Bytes proof_data;
	if (RNS::Reticulum::should_use_implicit_proof()) {
		proof_data = signature;
		TRACEF("Identity::prove: implicit proof data: %s", proof_data.toHex().c_str());
	}
	else {
		proof_data = packet.packet_hash() + signature;
		TRACEF("Identity::prove: explicit proof data: %s", proof_data.toHex().c_str());
	}
	// Reticulous "rx report": append our own rx of the proven packet AFTER the
	// proof data, outside the signature (which covers only packet_hash) —
	// int16 rssi dBm | int16 snr×10 | int8 antenna tx power dBm, big-endian.
	// Only when asked and we have a radio reading.
	//
	// The tx power is that of the interface the proven packet arrived on — the
	// same radio this proof leaves by — so the far end can pair the rssi it
	// measures on this proof with the power that produced it and read the path
	// loss directly. INT8_MIN when the interface has no such notion.
	//
	// A vanilla receiver length-rejects the longer proof, which is why rnsd
	// sends it only to peers that advertised the capability. See
	// Packet::prove_report and PacketReceipt::validate_proof.
	if (report_signal && !Type::isNan(packet.rssi())) {
		auto rnd = [](float x) -> int16_t { return (int16_t)(x < 0 ? x - 0.5f : x + 0.5f); };
		int16_t r = rnd(packet.rssi());
		int16_t s = Type::isNan(packet.snr()) ? 0 : rnd(packet.snr() * 10.0f);
		int txp = packet.receiving_interface()
		        ? packet.receiving_interface().tx_power_dbm() : INT8_MIN;
		if (txp < INT8_MIN || txp > INT8_MAX) txp = INT8_MIN;
		uint8_t tail[5] = { (uint8_t)((uint16_t)r >> 8), (uint8_t)r,
		                    (uint8_t)((uint16_t)s >> 8), (uint8_t)s,
		                    (uint8_t)(int8_t)txp };
		proof_data << Bytes(tail, sizeof(tail));
	}

	if (!destination) {
		TRACE("Identity::prove: proving packet with proof destination...");
		ProofDestination proof_destination = packet.generate_proof_destination();
		Packet proof(proof_destination, packet.receiving_interface(), proof_data, Type::Packet::PROOF);
		proof.send();
	}
	else {
		TRACE("Identity::prove: proving packet with specified destination...");
		Packet proof(destination, packet.receiving_interface(), proof_data, Type::Packet::PROOF);
		proof.send();
	}
}

void Identity::prove(const Packet& packet) const {
	prove(packet, {Type::NONE});
}
