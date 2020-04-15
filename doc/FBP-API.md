# FBP API
## Client
## Request

#### App-RequestReply/PubSub:

    //RPC Group
    Server
    announceService()
    retireService()
    readRequest()
    sendResult()

    Client
    introduceMe()
    detruceMe()
    sendRequest()
    readResult() 

    //PubSub Group
    P2P
    createTopic()
    destroyTopic() // ev
    publish(topic, msg)
    subscribe(topic)
    unsubscribe(topic)
    read(topic) -> newest msg, void

    //Capsuling protocol, feeds, general impl. from app
    
    old
    createChannel()
    destroyChannel(Channel)
    post(MSG, Channel)
    inviteToChannel(Channel, User)
    joinChannel(Channel)
    removeFromChannel(User)
    
    Up API - display to User

    Contract Client ISP
    //RPC Group
    ISP
    announceService()
    retireService()
    readRequest()
    sendResult()

    Client
    //introduceMe() -> unused already following
    //detruceMe() -> unused business contract ended
    sendRequest()
    readResult()

    Available ISP services
    C:introduceMe(serviceID, boolean) -> true=introduce, flase=detruce
    S:announce(serviceID, boolean) -> true=announce, flase=retire

    TODO: S:getNextRPC/meetCustomers/collectCustomers(serviceID) -> clientID,boolean* (stream)

    ==> Prototype-Pseudo Code: Client connects to a service via ONE ISP



#### Feed-Level:

    write()
    read()
    
    E2E Additions:
    -
    Feed in Feed:
    -

#### Protocol-Level:

    E2E:
    tbd - could be UDP stream etc.
    Feed in Feed:
    passToContract(action)
    

## Contract

#### App-Level:
General:

    connect(ISP)/makeContract()
    disconnect(ISP)/cancelContract()


#### Feed-Level:

    read()
    write()
    
    E2E Additions:
    -

    Feed in Feed Additions:
    embed(Feed)
    exctract(Feed)

#### Protocol-Level:

    followMe()
    forgetMe()

    pullFeeds()
    pushFeeds()

# ISP
## Contract
#### App-Level:

    add(User)
    add(Channel)
    remove(User)
    remove(Channel)
    registerFollowMe(User)
    registerForgetMe(User)

#### Feed-Level:
    
    E2E
    read(Feed) 
    write(Feed)
    on contract-Isp feed

    E2E Addition:
    forwardToTunnel(Feed)
    in case same connection is used to transfer

    Feed in Feed Additions:
    embed(Feed)
    exctract(Feed)
#### Protocol-Level:

    remarkUser(User)/subscribe(User)
    forgetUser(User)/unsubscribe(User)

    push(Feed)
    pull(Feed)

## Tunnel

#### App-Level:
    createTunnel(ISP)
    destroyTunnel(ISP)

    copy peers from connected ISPS
    forwarde them status of my peers followMe activity
    does user see other users from other isps? or is it blind? can user decline follow me after new usere wants to follow.



#### Feed-Level:
    
    read(Feed) 
    write(Feed)
    on tunnel-Isp feed

    E2E Additions:
    passTroughTunnel(Feed)
    in case same connection is used to transfer

    Feed in Feed Additions:
    read(Feed)
    write(Feed)
    embed(Feed)
    exctract(Feed)

#### Protocol-Level:
    

    ack()
    shorten()
    encap()