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

import { trytes } from '@web-ict/converter'
import { ADDRESS_LENGTH } from '@web-ict/transaction'

export function merkleForest({
    id,
    merkleForestIndex,
    seedTrits,
    depth,
    security,
    numberOfTrees,
    persistence,
    indexPersistence,
    merkleTreeWorker,
}) {
    let merkleForestPersistence = persistence({ path: './', id: `merkleForest_${id}_${merkleForestIndex.toString()}` })

    async function merkleTree(merkleTreeIndex) {
        return new Promise(async resolve => {
            const worker = merkleTreeWorker()
            const index = await indexPersistence.increment(2 ** depth)

            worker.postMessage([trytes(seedTrits, 0, seedTrits.length), index, depth, security].toString())
            worker.onmessage = async (event) => {
                const message = event.data || event
                worker.terminate()
                await merkleForestPersistence.put(
                    merkleTreeIndex,
                    message,
                );
                resolve(JSON.parse(message))
            }
        })
    }

    const merkleTrees = []
    for (let i = 0; i < numberOfTrees; i++) {
        merkleTrees[i] = merkleForestPersistence.get(i)
            .then(JSON.parse)
            .catch(error => {
                if (error.type === 'NotFoundError') {
                    return merkleTree(i)
                } else {
                    throw error
                }
            })
        merkleTrees[i].depth = depth
    }

    return {
        async increment() {
            let index = await merkleForestPersistence.increment()

            if (index >= 2 ** depth) {
                const ops = [{ type: 'put', key: 'index', value: JSON.stringify(0) }]
                for (let key = 0; key < numberOfTrees - 1; key++) {
                    ops.push({ type: 'put', key, value: await merkleForestPersistence.get(1) })
                }

                await merkleForestPersistence.batch(ops)

                merkleForestPersistence = persistence({ path: './', id: `merkleForest_${id}_${merkleForestIndex.toString()}` })
                index = await merkleForestPersistence.increment()

                for (let i = 0; i < numberOfTrees - 1; i++) {
                    merkleTrees[i] = merkleTrees[i + 1]
                }
                merkleTrees[numberOfTrees - 1] = merkleTree(numberOfTrees - 1)
                merkleTrees[numberOfTrees - 1].depth = depth
            }

            return { index, depth: merkleTrees[0].depth, root: await merkleTrees[0], nextRoot: await merkleTrees[1] }
        },
        async root() {
            return trytes(await merkleTree[0].address, 0, ADDRESS_LENGTH)
        },
        async nextRoot() {
            return trytes(await merkleTree[1].address, 0, ADDRESS_LENGTH)
        },
    }
}
