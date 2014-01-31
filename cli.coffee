#!/u:sr/bin/env coffee

###
Main command line for starphleet, this is the program you use on *your computer*
to control and provision a phleet, contrast this with the starphleet-\* commands
which are run on shipts in a phleet.
###

{docopt} = require 'docopt'
fs = require 'fs'
path = require 'path'
_ = require 'lodash'
handlebars = require 'handlebars'
async = require 'async'
md5 = require 'MD5'
AWS = require 'aws-sdk'
pkg = require(path.join(__dirname, "./package.json"))
colors = require 'colors'
request = require 'request'
os = require 'os'
yaml = require 'js-yaml'

EC2_INSTANCE_SIZE="m2.2xlarge"

doc = """
#{pkg.description}

Usage:
  starphleet init ec2
  starphleet info ec2 [--verbose]
  starphleet add ship ec2 <region>
  starphleet remove ship ec2 <region> <id>
  starphleet name ship ec2 <zone_id> <domain_name> <address>...
  starphleet -h | --help | --version

Notes:
  This uses the AWS API, so you will need these environment variables set:
    * AWS_ACCESS_KEY_ID
    * AWS_SECRET_ACCESS_KEY
    * STARPHLEET_HEADQUARTERS
    * STARPHLEET_PUBLIC_KEY
    * STARPHLEET_PRIVATE_KEY
    * EC2_INSTANCE_SIZE will be consulted, defaulting to #{EC2_INSTANCE_SIZE}

Description:
  This tool uses the AWS API for you to create a properly provisioned phleet
  including:
    * Setting up security policies
    * Setting up multiple container ships, which are hosts with a cute name
    * Spreading your phleet across availability zones

  init
    This takes an URL and a public key in a file. The URL points to your
    headquarters, and you need to be able to get at this without a login, so
    just give it your public git URL of your headquarters. The public key
    will be used for the 'ubuntu' account you can use to ssh directly to
    each ship in the phleet. This is a big feature over other PaaS, you can
    actually get at 'the machine'.

    You can fork https://github.com/wballard/starphleet.headquarters.git to
    start up a headquarters and save starting from scratch.

  info
    This will show you:
      * all about the load balancing across the ships
      * all the container ships in your phleet

  add ship
    Add a ship in a specific availability zone.

  remove ship
    Remove a ship by name, which you can get from 'info'.

"""
options = docopt doc, version: pkg.version

#All the exciting settings and globals
images =
  'us-east-1': 'ami-8f311fe6'
  'us-west-1': 'ami-c2fccc87'
  'eu-west-1': 'ami-d23cd5a5'
  'ap-southeast-1': 'ami-82c793d0'
zones = _.map _.keys(images), (x) -> new AWS.EC2 {region: x, maxRetries: 15}

isThereBadNews = (err) ->
  if /LoadBalancerNotFound/.test("#{err}")
    console.error "No load balancer found for #{process.env['STARPHLEET_HEADQUARTERS']}".yellow
    console.error "Have you run".yellow
    console.error "  starphleet init ec2".blue
    process.exit 1
  else if err
    console.error "#{err}".red
    process.exit 1

mustBeSet = (name) ->
  if not process.env[name]
    console.error "#{name} needs to be in your environment".red
    process.exit 1

niceToHave = (name, message) ->
  if not process.env[name]
    console.error "#{name} #{message}".yellow

if options.ec2
  mustBeSet 'AWS_ACCESS_KEY_ID'
  mustBeSet 'AWS_SECRET_ACCESS_KEY'

###
Init is all about setting up a .starphleet file with the key and url. This will
be used by subsequent commands when creating ships.
###

if options.init and options.ec2
  mustBeSet 'STARPHLEET_HEADQUARTERS'
  listeners = []
  listeners.push
    #on purpose TCP to do web sockets
    Protocol: 'TCP'
    LoadBalancerPort: 80
    InstancePort: 80
  listeners.push
    Protocol: 'TCP'
    LoadBalancerPort: 443
    InstancePort: 443
  initZone = (zone, callback) ->
    async.waterfall [
      #check for the starphleet security group
      (nestedCallback) ->
        zone.describeSecurityGroups {}, nestedCallback
      #and make the security group if needed
      (groups, nestedCallback) ->
        if _.some(groups.SecurityGroups, (x) -> x.GroupName is 'starphleet')
          nestedCallback undefined, groups
        else
          zone.createSecurityGroup {GroupName: 'starphleet', Description: 'Created by Starphleet'}, nestedCallback
      #hook up all the ports into the security group
      (ignore, nestedCallback) ->
        zone.describeSecurityGroups {GroupNames: ['starphleet']}, (err, groups) ->
          isThereBadNews err
          allowed_ports = [22, 80, 443]
          grantIfNeeded = (port, grantCallback) ->
            if _.some(groups.SecurityGroups[0].IpPermissions, (x) -> (x.FromPort is port and x.ToPort is port))
              grantCallback()
            else
              grant =
                GroupName: 'starphleet'
                IpPermissions: [
                  IpProtocol: 'tcp'
                  FromPort: port
                  ToPort: port
                  IpRanges: [{CidrIp: '0.0.0.0/0'}]
                ]
              zone.authorizeSecurityGroupIngress grant, grantCallback
          async.each allowed_ports, grantIfNeeded, (err) ->
            isThereBadNews err
            nestedCallback()
      #and now -- we are all set up and ready to run, but there are
      #no instances started just yet
    ], (err, results) ->
      isThereBadNews err
      callback()

  async.each zones, initZone, (err) ->
    isThereBadNews err
    process.exit 0

if options.add and options.ship and options.ec2
  mustBeSet 'STARPHLEET_HEADQUARTERS'
  mustBeSet 'STARPHLEET_PUBLIC_KEY', 'is not set, you will not be able to ssh ubuntu@host'
  niceToHave 'STARPHLEET_PRIVATE_KEY', 'is not set, you will only be able to access https git repos read only one way'
  url = process.env['STARPHLEET_HEADQUARTERS']
  zone = _.select(zones, (zone) -> zone.config.region is options['<region>'])[0]
  if not zone
    isThereBadNews "You must pick a region from #{_.map(zones, (x) -> x.config.region)}".red

  public_key_name = ''
  async.waterfall [
    #checking if we already have the key
    (callback) ->
      if process.env['STARPHLEET_PUBLIC_KEY']
        public_key_content =
          new Buffer(fs.readFileSync(process.env['STARPHLEET_PUBLIC_KEY'], 'utf8')).toString('base64')
        public_key_name = "starphleet-#{md5(public_key_content).substr(0,8)}"
        zone.describeKeyPairs {}, (err, keyFob) ->
          #adding if we lack the key
          if _.some(keyFob.KeyPairs, (x) -> x.KeyName is public_key_name)
            callback()
          else
            zone.importKeyPair {KeyName: public_key_name, PublicKeyMaterial: public_key_content}, ->
              callback()
      else
        callback()
    (callback) ->
      ami = images[options['<region>']]
      #leverage cloud-init cloud-config
      user_data =
        runcmd: [
          "apt-get install -y git",
          "git clone https://github.com/wballard/starphleet.git /starphleet",
          "/starphleet/scripts/starphleet-install",
          "starphleet-headquarters #{process.env['STARPHLEET_HEADQUARTERS']}"
        ]
        write_files: [
          {
            content: fs.readFileSync(process.env['STARPHLEET_PRIVATE_KEY'], 'utf8') if process.env['STARPHLEET_PRIVATE_KEY']
            path: '/var/starphleet/private_keys/starphleet'
          },
          {
            content: fs.readFileSync(process.env['STARPHLEET_PUBLIC_KEY'], 'utf8') if process.env['STARPHLEET_PRIVATE_KEY']
            path: '/var/starphleet/public_keys/starphleet.pub'
          }
        ]
        output: {all: '| tee -a /var/log/cloud-init-output.log'}
      todo =
        ImageId: ami
        MinCount: 1
        MaxCount: 1
        KeyName: public_key_name
        SecurityGroups: ['starphleet']
        UserData: new Buffer("#cloud-config\n" + yaml.safeDump(user_data)).toString('base64')
        InstanceType:  process.env['EC2_INSTANCE_SIZE'] or EC2_INSTANCE_SIZE
      zone.runInstances todo, callback
    (ran, callback) ->
      ids = _.map ran.Instances, (x) -> x.InstanceId
      todo =
        Resources: ids
        Tags: [
          {Key: 'Name', Value: 'Starphleet'},
          {Key: 'Headquarters', Value: "#{process.env['STARPHLEET_HEADQUARTERS']}"}
        ]
      zone.createTags todo, callback
  ], (err) ->
    isThereBadNews err
    process.exit 0

if options.info and options.ec2
  mustBeSet 'STARPHLEET_HEADQUARTERS'
  queryZone = (zone, zoneCallback) ->
    async.waterfall [
      (callback) ->
        zone.describeInstances Filters: [{Name: 'tag-key', Values:["Headquarters"]}]
          , callback
      #flattening away reservations as I don't care
      (data, callback) ->
        instances = []
        for reservation in data?.Reservations or []
          for instance in reservation.Instances
            instance.Region = zone.config.region
            if not instance.PublicDnsName
              instance.PublicDnsName = instance.State.Name
            instances.push instance
        callback undefined, instances
      #now poke at the instances via http to lean starphleet specifics
      (instances, callback) ->
        baseStatus = (instance, callback) ->
          request {url: "http://#{instance.PublicDnsName}/starphleet/status", timeout: 2000}, (err, res, body) ->
            #eating errors
            if options['--verbose'] and body
              instance.Services = yaml.safeLoad(body)
            else if body
              stats = yaml.safeLoad(body)
              instance.FreeRAM = "#{stats.free_ram}%"
              instance.FreeCPU = "#{stats.free_cpu}%"
              instance.FreeDisk = "#{stats.free_disk}%"
              instance.BaseStatus = true
            else
              instance.BaseStatus = false

            callback undefined, instance
        async.map instances, baseStatus, callback
      #tag-em!
      (instances, callback) ->
        tags = (instance, callback) ->
          zone.describeTags Filters: [{Name: 'resource-id', Values: [instance.InstanceId]}], (err, data) ->
            instance.Headquarters = _.select(data.Tags, (x) -> x.Key is 'Headquarters')?[0]?.Value
            callback undefined, instance
        async.map instances, tags, callback
      #status relevant to starphleet, not raw EC2
      (instances, callback) ->
        for instance in instances
          if instance.BaseStatus
            instance.Status = 'ready'
          else if instance.State.Name is 'running'
            instance.Status = 'building'
          else
            instance.Status = 'offline'
          instance.Logstream = "http://#{instance.PublicDnsName}/starphleet/logstream"
          instance.Diagnostic = "http://#{instance.PublicDnsName}/starphleet/status"
          instance.AdmiralSSH = "ssh admiral@#{instance.PublicDnsName}"
        callback undefined, instances or []
    ], zoneCallback

  async.map zones, queryZone, (err, all) ->
    isThereBadNews err
    sliced = _.map all, (zoneInstances) ->
      _.map zoneInstances, (instance) ->
        _.pick instance, 'Headquarters', 'Region', 'InstanceType',
          'InstanceId', 'PublicDnsName', 'Status', 'Logstream',
          'Diagnostic', 'AdmiralSSH', 'Services', 'FreeRAM', 'FreeCPU', 'FreeDisk'
    sliced = _.flatten(sliced)
    if sliced.length
      console.log yaml.dump(sliced)
    else
      console.error "Run".yellow
      console.error "  starphleet add ship ec2 [region]".blue
      console.error "valid regions #{_.map(zones, (x) -> x.config.region)}".yellow
    process.exit 0

if options.remove and options.ship and options.ec2
  mustBeSet 'STARPHLEET_HEADQUARTERS'
  zone = _.select(zones, (zone) -> zone.config.region is options['<region>'])[0]
  if not zone
    isThereBadNews "You must pick a region from #{_.map(zones, (x) -> x.config.region)}".red
  async.waterfall [
    (callback) ->
      zone.describeInstanceStatus
        InstanceIds: [options['<id>']]
      , callback
    (statuses, callback) ->
      if statuses.InstanceStatuses.length
        zone.terminateInstances
          InstanceIds: [options['<id>']]
        , callback
      else
        callback undefined, null
    ], (err) ->
      isThereBadNews err
      process.exit 0

if options.name and options.ship and options.ec2
  route53 = new AWS.Route53 {region: 'us-east-1'}
  async.waterfall [
    #need to check for an existing record, shame there is no UPDATE...
    (nestedCallback) ->
      route53.listResourceRecordSets {HostedZoneId: options['<zone_id>'], StartRecordName: "#{os.hostname()}.#{options['<domain_name>']}", StartRecordType: 'A', MaxItems: '1'}, nestedCallback
    (records, nestedCallback) ->
      change =
        HostedZoneId: options['<zone_id>']
        ChangeBatch:
          Comment: 'Starphleet name update'
          Changes: []
      if records.ResourceRecordSets?[0]
        change.ChangeBatch.Changes.push
          Action: 'DELETE'
          ResourceRecordSet: records.ResourceRecordSets[0]
      change.ChangeBatch.Changes.push
        Action: 'CREATE'
        ResourceRecordSet:
          Name: "#{os.hostname()}.#{options['<domain_name>']}"
          Type: 'A'
          TTL: 300
          ResourceRecords: _.map options['<address>'], (x) -> Value: x
      route53.changeResourceRecordSets change, nestedCallback
  ], (err, results) ->
    isThereBadNews err
    console.log JSON.stringify results
    process.exit 0
