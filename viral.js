/*
Permission is hereby granted, perpetual, worldwide, non-exclusive, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:



1. The Software cannot be used in any form or in any substantial portions for development, maintenance and for any other purposes, in the military sphere and in relation to military products, including, but not limited to:

a. any kind of armored force vehicles, missile weapons, warships, artillery weapons, air military vehicles (including military aircrafts, combat helicopters, military drones aircrafts), air defense systems, rifle armaments, small arms, firearms and side arms, melee weapons, chemical weapons, weapons of mass destruction;

b. any special software for development technical documentation for military purposes;

c. any special equipment for tests of prototypes of any subjects with military purpose of use;

d. any means of protection for conduction of acts of a military nature;

e. any software or hardware for determining strategies, reconnaissance, troop positioning, conducting military actions, conducting special operations;

f. any dual-use products with possibility to use the product in military purposes;

g. any other products, software or services connected to military activities;

h. any auxiliary means related to abovementioned spheres and products.



2. The Software cannot be used as described herein in any connection to the military activities. A person, a company, or any other entity, which wants to use the Software, shall take all reasonable actions to make sure that the purpose of use of the Software cannot be possibly connected to military purposes.



3. The Software cannot be used by a person, a company, or any other entity, activities of which are connected to military sphere in any means. If a person, a company, or any other entity, during the period of time for the usage of Software, would engage in activities, connected to military purposes, such person, company, or any other entity shall immediately stop the usage of Software and any its modifications or alterations.



4. Abovementioned restrictions should apply to all modification, alteration, merge, and to other actions, related to the Software, regardless of how the Software was changed due to the abovementioned actions.



The above copyright notice and this permission notice shall be included in all copies or substantial portions, modifications and alterations of the Software.



THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

import { integerValue, integerValueToTrits, trytes, trytesToTrits, TRYTE_WIDTH, RADIX, TRUE, UNKNOWN } from '@web-ict/converter'
import { ISS, SECURITY_LEVEL_TRITS, BUNDLE_FRAGMENT_TRYTE_LENGTH, KEY_SIGNATURE_FRAGMENT_LENGTH } from '@web-ict/iss'
import { ADDRESS_OFFSET, ADDRESS_END, ADDRESS_LENGTH, MESSAGE_OR_SIGNATURE_LENGTH, MESSAGE_OR_SIGNATURE_OFFSET, EXTRA_DATA_DIGEST_LENGTH } from '@web-ict/transaction'
import { essence, transactionTrits, updateBundleNonce } from '@web-ict/bundle/src/bundle.js'
import { createPersistence } from '@web-ict/persistence'
import IPFS from 'ipfs-core'
import Repo from 'ipfs-repo'
import DataStore from 'datastore-level'
import { integerValueLengthInTrits, stringToTrytes, trytesToString } from './converter'
import { mask, unmask } from './encryption'
import { merkleForest } from './merkle-forest'
import { weightMagnitude } from './weight-magnitude'

const HASH_LENGTH = 243
const MAX_MERKLE_TREE_DEPTH = 40
const PUBLIC_FLAG_OFFSET = 0
const PUBLIC_FLAG_LENGTH = 1
const INDEX_OFFSET = PUBLIC_FLAG_OFFSET + PUBLIC_FLAG_LENGTH
const INDEX_LENGTH = integerValueLengthInTrits(2 ** MAX_MERKLE_TREE_DEPTH - 1)
const DEPTH_OFFSET = INDEX_OFFSET + INDEX_LENGTH
const DEPTH_LENGTH = integerValueLengthInTrits(MAX_MERKLE_TREE_DEPTH)
const SECURITY_OFFSET = DEPTH_OFFSET + DEPTH_LENGTH
const SECURITY_LENGTH = 1
const PAYLOAD_LENGTH_OFFSET = SECURITY_OFFSET + SECURITY_LENGTH
const PAYLOAD_LENGTH_LENGTH = 81
const PAYLOAD_OFFSET = PAYLOAD_LENGTH_OFFSET + PAYLOAD_LENGTH_LENGTH
const POST_TYPE_LENGTH = 1
export const POST_TYPES = {
    POST: -1,
    RE: 0,
    VOTE: 1,
}
const VOTE_TYPE_LENGTH = 1
const MASK_INDEX_LENGTH = 81

export function viral({ Curl729_27, ixi, store, merkleTreeWorker, maxWeightMagnitude, numberOfTrees }) {
    const persistence = createPersistence(store)
    const iss = ISS(Curl729_27)
    const ipfsStore = function(path, options) {
        return new DataStore(path, {
            ...options,
            db: store,
        })
    }
    const ipfs = IPFS.create({
        repo: new Repo('/tmp/custom-repo/.ipfs', {
            storageBackends: {
                root: ipfsStore,
                blocks: ipfsStore,
                keys: ipfsStore,
                pins: ipfsStore,
                datastore: ipfsStore
            }
        })
    })
    const contacts = new Map()

    function userAgent({ seed, depth, security }) {
        const seedTrits = trytesToTrits(seed, new Int8Array(HASH_LENGTH))
        const id = trytes(
            iss.addressFromDigests(iss.digests(iss.key(iss.subseed(seedTrits, 0), 1))),
            0,
            ADDRESS_LENGTH
        )
        const indexPersistence = persistence({ path: './', id: `index_${id}` })
        const contactsPersistence = persistence({ path: './', id: `contacts_${id}` })
        const merkleForestIndexPersistence = persistence({ path: './', id: `merkleForestIndex_${id}` })
        const { increment } = merkleForest({
            id,
            merkleForestIndex: -1,
            seedTrits,
            depth,
            security,
            numberOfTrees,
            persistence,
            indexPersistence,
            merkleTreeWorker,
        })

        contactsPersistence.createReadStream()
            .on('data', ({ value }) => {
                const contact = JSON.parse(value)
                if (contact.index) {
                    contact.increment = merkleForest({
                        id,
                        merkleForestIndex: contact.index,
                        seedTrits,
                        depth,
                        security,
                        numberOfTrees,
                        persistence,
                        indexPersistence,
                        merkleTreeWorker,
                    }).increment
                    contact.incrementMaskIndex = persistence({ path: './', id: `maskIndex_${id}_${contact.index.toString()}` }).increment
                    contact.remoteRoots.forEach(root => contacts.set(root, contact))
                    contacts.set(contact.index, contact)
                }
            })

        function authenticate({ publicFlag, payload, root, index, depth }) {
            const transactions = []
            const issuanceTimestamp = Math.floor(Date.now() / 1000)
            const tag = trytesToTrits('VIRAL')
            const { leafIndex, siblings } = iss.getMerkleProof(root, index)
            const message = new Int8Array(
                PUBLIC_FLAG_LENGTH +
                INDEX_LENGTH +
                DEPTH_LENGTH +
                SECURITY_LENGTH +
                PAYLOAD_LENGTH_LENGTH +
                payload.length +
                siblings.length
            )
            message[PUBLIC_FLAG_OFFSET] = publicFlag
            integerValueToTrits(index, message, INDEX_OFFSET)
            integerValueToTrits(depth, message, DEPTH_OFFSET)
            message[SECURITY_OFFSET] = SECURITY_LEVEL_TRITS[security]
            integerValueToTrits(payload.length, message, PAYLOAD_LENGTH_OFFSET)
            message.set(payload, PAYLOAD_OFFSET)
            message.set(siblings, PAYLOAD_OFFSET + payload.length)

            const extraDataDigest = new Int8Array(EXTRA_DATA_DIGEST_LENGTH)
            const extraDataDigestPreimage = new Int8Array(payload.length + ADDRESS_LENGTH + INDEX_LENGTH)
            extraDataDigestPreimage.set(payload)
            extraDataDigestPreimage.set(root.address, payload.length)
            integerValueToTrits(index, extraDataDigestPreimage, payload.length + ADDRESS_LENGTH)
            Curl729_27.get_digest(extraDataDigestPreimage, 0, extraDataDigestPreimage.length, extraDataDigest, 0)

            for (let i = 0; i < 1 + Math.floor(message.length / MESSAGE_OR_SIGNATURE_LENGTH); i++) {
                transactions.push(transactionTrits({
                    type: TRUE,
                    messageOrSignature: message.slice(i * MESSAGE_OR_SIGNATURE_LENGTH, (i + 1) * MESSAGE_OR_SIGNATURE_LENGTH),
                    address: root.address,
                    extraDataDigest,
                    issuanceTimestamp,
                    tag,
                }))
            }

            for (let i = 0; i < security; i++) {
                transactions.push(transactionTrits({
                    type: UNKNOWN,
                    address: root.address,
                    extraDataDigest,
                    issuanceTimestamp,
                    tag,
                }))
            }

            const key = iss.key(iss.subseed(seedTrits, leafIndex), security)
            const bundle = updateBundleNonce(Curl729_27)(transactions, security)
            const bundleTrytes = iss.bundleTrytes(bundle, security)

            for (let i = 0; i < security; i++) {
                transactions[transactions.length - security + i].set(
                    iss.signatureFragment(
                        bundleTrytes.slice(i * BUNDLE_FRAGMENT_TRYTE_LENGTH, (i + 1) * BUNDLE_FRAGMENT_TRYTE_LENGTH),
                        key.slice(i * KEY_SIGNATURE_FRAGMENT_LENGTH, (i + 1) * KEY_SIGNATURE_FRAGMENT_LENGTH)
                    ),
                    MESSAGE_OR_SIGNATURE_OFFSET
                )
            }

            return transactions
        }

        return {
            async post(text, images=[]) {
                const filePaths = []

                for (const image of images.map(image => new Uint8Array(image))) {
                    filePaths.push((await (await ipfs).add(image)).path)
                }

                const textTrits = trytesToTrits(stringToTrytes(text))
                const filePathsTrytes = filePaths.map(stringToTrytes)
                const filePathsTrits = new Int8Array((1 + filePaths.length) * 81 + filePathsTrytes.reduce((acc, t) => acc += t.length * TRYTE_WIDTH, 0))
                integerValueToTrits(filePaths.length, filePathsTrits, 0)
                let offset = 0
                filePathsTrytes.forEach((filePathTrytes, i) => {
                    integerValueToTrits(filePathTrytes.length * TRYTE_WIDTH, filePathsTrits, (1 + i) * 81)
                    trytesToTrits(filePathTrytes, filePathsTrits, (1 + filePaths.length) * 81 + offset)
                    offset += filePathTrytes.length * TRYTE_WIDTH
                })

                const payload = new Int8Array(POST_TYPE_LENGTH + ADDRESS_LENGTH + 81 + textTrits.length + filePathsTrits.length)
                const { index, depth, root, nextRoot } = await increment()
                
                payload[0] = POST_TYPES.POST
                payload.set(nextRoot.address, POST_TYPE_LENGTH)
                integerValueToTrits(textTrits.length, payload, POST_TYPE_LENGTH + ADDRESS_LENGTH)
                payload.set(textTrits, POST_TYPE_LENGTH + ADDRESS_LENGTH + 81)
                payload.set(filePathsTrits, POST_TYPE_LENGTH + ADDRESS_LENGTH + 81 + textTrits.length)

                ixi.attachToTangle(authenticate({ publicFlag: 1, payload, root, index, depth }), 1)
            },

            async reply(reference, text, images=[]) {
                const filePaths = []

                for (const image of images.map(image => new Uint8Array(image))) {
                    filePaths.push((await (await ipfs).add(image)).path)
                }

                const textTrits = trytesToTrits(stringToTrytes(text))
                const filePathsTrytes = filePaths.map(stringToTrytes)
                const filePathsTrits = new Int8Array((1 + filePaths.length) * 81 + filePathsTrytes.reduce((acc, t) => acc += t.length * TRYTE_WIDTH, 0))
                integerValueToTrits(filePaths.length, filePathsTrits, 0)
                let offset = 0
                filePathsTrytes.forEach((filePathTrytes, i) => {
                    integerValueToTrits(filePathTrytes.length * TRYTE_WIDTH, filePathsTrits, (1 + i) * 81)
                    trytesToTrits(filePathTrytes, filePathsTrits, (1 + filePaths.length) * 81 + offset)
                    offset += filePathTrytes.length * TRYTE_WIDTH
                })

                const payload = new Int8Array(POST_TYPE_LENGTH + EXTRA_DATA_DIGEST_LENGTH + ADDRESS_LENGTH + 81 + textTrits.length + filePathsTrits.length)
                const { index, depth, root, nextRoot } = await increment()

                payload[0] = POST_TYPES.RE
                payload.set(trytesToTrits(reference), POST_TYPE_LENGTH)
                payload.set(nextRoot, POST_TYPE_LENGTH + EXTRA_DATA_DIGEST_LENGTH)
                integerValueToTrits(textTrits.length, payload, POST_TYPE_LENGTH + EXTRA_DATA_DIGEST_LENGTH + ADDRESS_LENGTH)
                payload.set(textTrits, POST_TYPE_LENGTH + EXTRA_DATA_DIGEST_LENGTH + ADDRESS_LENGTH + 81)
                payload.set(filePathsTrits, POST_TYPE_LENGTH + EXTRA_DATA_DIGEST_LENGTH + ADDRESS_LENGTH + 81 + textTrits.length)

                ixi.attachToTangle(authenticate({ publicFlag: 1, payload, root, index, depth }), 1)
            },

            async vote(reference, type) {
                const payload = new Int8Array(POST_TYPE_LENGTH + EXTRA_DATA_DIGEST_LENGTH + ADDRESS_LENGTH + VOTE_TYPE_LENGTH)
                const { index, depth, root, nextRoot } = await increment()

                payload[0] = POST_TYPES.VOTE
                payload.set(trytesToTrits(reference), POST_TYPE_LENGTH)
                payload.set(nextRoot, POST_TYPE_LENGTH + EXTRA_DATA_DIGEST_LENGTH)
                payload[POST_TYPE_LENGTH + EXTRA_DATA_DIGEST_LENGTH + ADDRESS_LENGTH] = type

                ixi.attachToTangle(authenticate({ publicFlag: 1, payload, root, index, depth }), 1)
            },

            async message(contactIndex, text) {
                const contact = contacts.get(contactIndex)
                const { index, depth, root, nextRoot } = await contact.increment()
                const textTrits = trytesToTrits(stringToTrytes(text))
                const maskIndex = contact.incrementMaskIndex()

                const payloadToMask = new Int8Array(ADDRESS_LENGTH + textTrits.length)
                payloadToMask.set(nextRoot.address, 0)
                payloadToMask.set(textTrits, ADDRESS_LENGTH)

                integerValueToTrits(maskIndex, payload, 0)
                payload.set(mask(Curl729_27, payloadToMask, iss.subseed(contact.localKey, maskIndex)), MASK_INDEX_LENGTH)

                ixi.attachToTangle(authenticate({ publicFlag: -1, payload, root, index, depth }), 1)
            },

            contact(localKey) {
                const merkleForestIndex = merkleForestIndexPersistence.increment()
                const forest = merkleForestIndex.then((i) => merkleForest({
                    id,
                    merkleForestIndex: i,
                    seedTrits,
                    depth,
                    security,
                    numberOfTrees,
                    persistence,
                    indexPersistence,
                    merkleTreeWorker,
                }))

                return {
                    async getLocalInfo() {
                        return {
                            root: await forest.root(),
                            key: localKey,
                        }
                    },
                    async addRemoteInfo({ root, key }) {
                        const contact = {
                            index: await merkleForestIndex,
                            localKey,
                            remoteRoots: [root],
                            remoteKey: key,
                            numberOfAnalyzedMessages: [0],
                        }
                        contact.increment = forest.increment
                        contact.incrementMaskIndex = persistence({ path: './', id: `maskIndex_${id}_${contact.index.toString()}` }).increment
                        contacts.set(root, contact)
                        await contactsPersistence.set(contact.index, JSON.stringify(contact))
                    },
                }
            },

            deleteContact(index) {
                contacts.delete(contact.index)
                contacts.forEach(contact => {
                    if (contact.index === index) {
                        contacts.delete(contact.remoteRoot)
                    }
                })
                return contactsPersistence.del(index)
            },

            setDepth(value) {
                depth = value
            },

            getId() {
                return id
            }
        }
    }

    let listener
    let isSubscribed = false
    const nonAnalyzedTails = new Map()
    const analyzedExtraDataDigests = new Set()
    const posts = new Map()
    const tags = new Map()
    const postsByReference = new Map()

    return {
        userAgent,
        subscribe(callback, id) {
            if (isSubscribed) {
                return
            }

            isSubscribed = true

            listener = (transaction) => {
                if (
                    transaction.tailFlag === TRUE &&
                    transaction.tag.slice(0, 'VIRAL'.length) === 'VIRAL' &&
                    !analyzedExtraDataDigests.has(transaction.extraDataDigest)
                ) {
                    nonAnalyzedTails.set(transaction.hash, transaction)
                }
            }

            let contactsPersistence
            if (id) {
                contactsPersistence = persistence({ path: './', id: `contacts_${id}` })
            }

            function applyVote(post, reference, callback) {
                const delta = post.voteType * post.ownWeight
                reference.weight += delta

                if (reference.weight > 0) {
                    const analyzedTags = new Set()
                    ;(reference.text.match(/#\w+/g) || []).map(value => value.slice(1)).forEach(value => {
                        if (!analyzedTags.has(value)) {
                            analyzedTags.add(value)

                            const tag = tags.get(value)
                            tag.weight += delta

                            callback({ tag: { ...tag } })
                        }
                    })
                }

                if (post.voteType > 0) {
                    reference.upvotes += 1
                } else {
                    reference.downvotes +=1
                }

                callback({
                    post: { ...reference }
                })
            }

            (function analyzeTails() {
                nonAnalyzedTails.forEach(async transaction => {
                    const bundleTransactions = ixi.collectBundle(transaction)

                    if (bundleTransactions.length > 0) {
                        nonAnalyzedTails.delete(transaction.hash)

                        const messageOrSignature = new Int8Array(bundleTransactions.length * MESSAGE_OR_SIGNATURE_LENGTH)
                        for (let i = 0; i < bundleTransactions.length; i++) {
                            messageOrSignature.set(bundleTransactions[i].messageOrSignature, i * MESSAGE_OR_SIGNATURE_LENGTH)
                        }

                        const index = integerValue(messageOrSignature, INDEX_OFFSET, INDEX_LENGTH)
                        const depth = integerValue(messageOrSignature, DEPTH_OFFSET, DEPTH_LENGTH)
                        const security = SECURITY_LEVEL_TRITS.indexOf(messageOrSignature[SECURITY_OFFSET])
                        const payloadLength = integerValue(messageOrSignature, PAYLOAD_LENGTH_OFFSET, PAYLOAD_LENGTH_LENGTH)

                        if (PAYLOAD_OFFSET + payloadLength > messageOrSignature.length - security * MESSAGE_OR_SIGNATURE_LENGTH) {
                            return
                        }

                        let offset = PAYLOAD_OFFSET
                        const payload = messageOrSignature.slice(offset, (offset += payloadLength))
                        const siblings = messageOrSignature.slice(offset, (offset += depth * HASH_LENGTH))

                        const extraDataDigest = new Int8Array(EXTRA_DATA_DIGEST_LENGTH)
                        const extraDataDigestPreimage = new Int8Array(payload.length + ADDRESS_LENGTH + INDEX_LENGTH)
                        extraDataDigestPreimage.set(payload)
                        extraDataDigestPreimage.set(transaction.trits.slice(ADDRESS_OFFSET, ADDRESS_END), payload.length)
                        integerValueToTrits(index, extraDataDigestPreimage, payload.length + ADDRESS_LENGTH)
                        Curl729_27.get_digest(extraDataDigestPreimage, 0, extraDataDigestPreimage.length, extraDataDigest, 0)

                        if (trytes(extraDataDigest, 0, HASH_LENGTH) === transaction.extraDataDigest) {
                            const bundle = new Int8Array(HASH_LENGTH)
                            const essenceTrits = essence(bundleTransactions.map(({ trits }) => trits))
                            Curl729_27.get_digest(essenceTrits, 0, essenceTrits.length, bundle, 0)
                            const bundleTrytes = iss.bundleTrytes(bundle, security)
                            const digests = new Int8Array(security * HASH_LENGTH)

                            for (let i = 0; i < security; i++) {
                                digests.set(
                                    iss.digest(
                                        bundleTrytes.slice(
                                            i * BUNDLE_FRAGMENT_TRYTE_LENGTH,
                                            (i + 1) * BUNDLE_FRAGMENT_TRYTE_LENGTH
                                        ),
                                        bundleTransactions[1 + Math.floor(offset / MESSAGE_OR_SIGNATURE_LENGTH) + i].messageOrSignature
                                    ),
                                    i * HASH_LENGTH
                                )
                            }

                            if (trytes(iss.getMerkleRoot(iss.addressFromDigests(digests), siblings, index, depth), 0, HASH_LENGTH) === transaction.address) {
                                analyzedExtraDataDigests.add(transaction.extraDataDigest)

                                if (messageOrSignature[PUBLIC_FLAG_OFFSET] === -1) {
                                    const contact = contacts.get(transaction.address)

                                    if (contact) {
                                        const unmaskedPayload = unmask(Curl729_27, payload.slice(MASK_INDEX_LENGTH), iss.subseed(contact.remoteKey, integerValue(payload, 0, MASK_INDEX_LENGTH)))
                                        const nextRoot = trytes(unmaskedPayload.slice(0, ADDRESS_LENGTH), 0, ADDRESS_LENGTH)

                                        contactsPersistence.get(nextRoot).catch((error) => {
                                            if (error.type === 'NotFoundError') {
                                                contact.remoteRoots.push(nextRoot)
                                                contact.numberOfAnalyzedMessages.push(0)
                                                contacts.set(nextRoot, contact)
                                                contactsPersistence.set(contact.index, JSON.stringify(contact))
                                            }
                                        })

                                        if (++contact.numberOfAnalyzedMessages[contacts.remoteRoots.indexOf(transaction.address)] === 2 ** depth) {
                                            contacts.delete(transaction.address)
                                            contact.remoteRoots.splice(contacts.remoteRoots.indexOf(transaction.address), 1)
                                            contact.numberOfAnalyzedMessages.splice(contacts.remoteRoots.indexOf(transaction.address), 1)
                                        }
                                        contactsPersistence.set(contact.index, JSON.stringify(contact))

                                        callback({
                                            message: {
                                                index,
                                                contactIndex: contact.index,
                                                timestamp: transaction.issuanceTimestamp,
                                                root: transaction.address,
                                                text: trytesToString(trytes(unmaskedPayload, ADDRESS_LENGTH, unmaskedPayload.length - ADDRESS_LENGTH))
                                            }
                                        })
                                    }
                                } else {
                                    const post = {
                                        type: payload[0],
                                        index,
                                        hash: transaction.hash,
                                        ownWeight: bundleTransactions.reduce((acc, { hash }) => acc += RADIX ** weightMagnitude(hash, maxWeightMagnitude), 0),
                                        extraDataDigest: transaction.extraDataDigest,
                                        timestamp: transaction.issuanceTimestamp,
                                        root: transaction.address,
                                        replies: new Set(),
                                        reposts: new Set(),
                                        upvotes: 0,
                                        downvotes: 0,
                                    }
                                    let reference
                                    let textLength
                                    let usernameAndText
                                    let textIndex
                                    let filePaths = []
                                    let filePathsLength
                                    let offset

                                    post.weight = post.ownWeight

                                    switch (post.type) {
                                        case POST_TYPES.POST:
                                            if (payloadLength <= POST_TYPE_LENGTH + ADDRESS_LENGTH) {
                                                return
                                            }

                                            post.nextRoot = trytes(payload, POST_TYPE_LENGTH, ADDRESS_LENGTH)
                                            textLength = integerValue(payload, POST_TYPE_LENGTH + ADDRESS_LENGTH, 81)
                                            usernameAndText = trytesToString(trytes(payload, POST_TYPE_LENGTH + ADDRESS_LENGTH + 81, textLength))
                                            textIndex = usernameAndText.indexOf(':') + 1
                                            if (textIndex === 0) {
                                                return
                                            }
                                            post.username = usernameAndText.slice(0, textIndex - 1)
                                            post.text = usernameAndText.slice(textIndex)
                                            
                                            filePathsLength = integerValue(payload, POST_TYPE_LENGTH + ADDRESS_LENGTH + 81 + textLength, 81)
                                            post.images = []

                                            offset = 0
                                            for (let i = 0; i < filePathsLength; i++) {
                                                const filePathLength = integerValue(payload, POST_TYPE_LENGTH + ADDRESS_LENGTH + 81 + textLength + (1 + i) * 81, 81)
                                                filePaths.push(trytesToString(trytes(payload, POST_TYPE_LENGTH + ADDRESS_LENGTH + 81 + textLength + (1 + filePathsLength) * 81 + offset, filePathLength)))
                                                offset += filePathLength
                                            }

                                            for (const filePath of filePaths) {
                                                for await (const file of (await ipfs).get(filePath)) {
                                                    if (!file.content) continue;
                                                    const content = []
                                                    for await (const chunk of file.content) {
                                                        content.push(chunk)
                                                    }
                                                    
                                                    const buffer = new Uint8Array(content.reduce((acc, chunk) => acc += chunk.length, 0))
                                                    let offset = 0
                                                    for (const chunk of content) {
                                                        buffer.set(chunk, offset)
                                                        offset += chunk.length
                                                    }

                                                    post.images.push(buffer)
                                                }
                                            }

                                            posts.set(post.extraDataDigest, post)

                                            callback({ post: { ...post } })
                                            
                                            break

                                        case POST_TYPES.RE:
                                            if (payloadLength < POST_TYPE_LENGTH + EXTRA_DATA_DIGEST_LENGTH + ADDRESS_LENGTH) {
                                                return
                                            }

                                            post.reference = trytes(payload, POST_TYPE_LENGTH, EXTRA_DATA_DIGEST_LENGTH)
                                            post.nextRoot = trytes(payload, POST_TYPE_LENGTH + EXTRA_DATA_DIGEST_LENGTH, ADDRESS_LENGTH)
                                            textLength = integerValue(payload, POST_TYPE_LENGTH + EXTRA_DATA_DIGEST_LENGTH + ADDRESS_LENGTH, 81)
                                            usernameAndText = trytesToString(trytes(payload, POST_TYPE_LENGTH + EXTRA_DATA_DIGEST_LENGTH + ADDRESS_LENGTH + 81, textLength))
                                            textIndex = usernameAndText.indexOf(':') + 1
                                            if (textIndex === 0) {
                                                return
                                            }
                                            post.username = usernameAndText.slice(0, textIndex - 1)
                                            post.text = usernameAndText.slice(textIndex)

                                            filePathsLength = integerValue(payload, POST_TYPE_LENGTH + EXTRA_DATA_DIGEST_LENGTH + ADDRESS_LENGTH + 81 + textLength, 81)
                                            post.images = []

                                            offset = 0
                                            for (let i = 0; i < filePathsLength; i++) {
                                                const filePathLength = integerValue(payload, POST_TYPE_LENGTH + EXTRA_DATA_DIGEST_LENGTH + ADDRESS_LENGTH + 81 + textLength + (1 + i) * 81, 81)
                                                filePaths.push(trytesToString(trytes(payload, POST_TYPE_LENGTH + EXTRA_DATA_DIGEST_LENGTH + ADDRESS_LENGTH + 81 + textLength + (1 + filePathsLength) * 81 + offset, filePathLength)))
                                                offset += filePathLength
                                            }

                                            for (const filePath of filePaths) {
                                                console.log(filePath)
                                                for await (const file of (await ipfs).get(filePath)) {
                                                    if (!file.content) continue;
                                                    const content = []
                                                    for await (const chunk of file.content) {
                                                        content.push(chunk)
                                                    }
                                                    
                                                    const buffer = new Uint8Array(content.reduce((acc, chunk) => acc += chunk.length, 0))
                                                    let offset = 0
                                                    for (const chunk of content) {
                                                        buffer.set(chunk, offset)
                                                        offset += chunk.length
                                                    }

                                                    post.images.push(buffer)
                                                }
                                            }

                                            reference = posts.get(post.reference)
                                            if (reference) {
                                                if (post.text === '' && post.images.length === 0) {
                                                    reference.reposts.add(post)
                                                } else {
                                                    reference.replies.add(post)
                                                }
                                                post.referencePost = reference

                                                callback({ post: { ...reference } })
                                                callback({ post: { ...post } })
                                            } else {
                                                let referrers = postsByReference.get(post.reference)
                                                if (referrers === undefined) {
                                                    referrers = new Set()
                                                }
                                                referrers.add(post)
                                                postsByReference.set(post.reference, referrers)
                                            }

                                            posts.set(post.extraDataDigest, post)

                                            break

                                        case POST_TYPES.VOTE:
                                            if (payloadLength < POST_TYPE_LENGTH + EXTRA_DATA_DIGEST_LENGTH + ADDRESS_LENGTH + VOTE_TYPE_LENGTH) {
                                                return
                                            }

                                            post.reference = trytes(payload, POST_TYPE_LENGTH, EXTRA_DATA_DIGEST_LENGTH)
                                            post.nextRoot = trytes(payload, POST_TYPE_LENGTH + EXTRA_DATA_DIGEST_LENGTH, ADDRESS_LENGTH)
                                            post.voteType = payload[POST_TYPE_LENGTH + EXTRA_DATA_DIGEST_LENGTH + ADDRESS_LENGTH]

                                            reference = posts.get(post.reference)
                                            if (reference !== undefined) {
                                                applyVote(post, reference, callback)
                                            } else {
                                                let referrers = postsByReference.get(post.reference)
                                                if (referrers === undefined) {
                                                    referrers = new Set()
                                                }
                                                referrers.add(post)
                                                postsByReference.set(post.reference, referrers)
                                            }
                                    }

                                    if (post.text) {
                                        let analyzedTags = new Set()
                                        ;(post.text.match(/#\w+/g) || []).map(value => value.slice(1)).forEach(value => {
                                            if (!analyzedTags.has(value)) {
                                                analyzedTags.add(value)

                                                let tag = tags.get(value)
                                                if (tag === undefined) {
                                                    tag = {
                                                        value,
                                                        weight: post.weight,
                                                        posts: new Set(),
                                                    }
                                                    tags.set(value, tag)
                                                }

                                                tag.posts.add(post)
    
                                                callback({ tag: { ...tag } })
                                            }
                                        })

                                        const referrers = postsByReference.get(transaction.extraDataDigest)
                                        if (referrers !== undefined) {
                                            referrers.forEach(referrer => {
                                                if (referrer.type === POST_TYPES.VOTE) {
                                                    applyVote(referrer, post, callback)
                                                } else {
                                                    if (post.text === '') {
                                                        post.reposts.add(post)
                                                    } else {
                                                        post.replies.add(post)
                                                    }
                                                    referrer.referencePost = post

                                                    callback({ post: { ...referrer } })
                                                }
                                            })
                                            postsByReference.delete(transaction.extraDataDigest)
                                        }
                                    }
                                }
                            }
                        }
                    }
                })

                if (isSubscribed) {
                    setTimeout(analyzeTails, 100)
                }
            })()

            ixi.addListener(listener)
        },

        unsubscribe() {
            if (isSubscribed) {
                isSubscribed = false
                ixi.removeListener(listener)
            }
        } 
    }
}
