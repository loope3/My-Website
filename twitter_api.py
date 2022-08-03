from email.headerregistry import ContentTransferEncodingHeader
import tweepy
import configparser

#read configs

config = configparser.ConfigParser()
config.read('config.ini')

api_key = config['twitter']['api_key']
api_key_secret = config['twitter']['api_key_secret']

access_token = config['twitter']['access_token']
access_token_secret = config['twitter']['access_token_secret']

bearer_token = 'AAAAAAAAAAAAAAAAAAAAAPu4egEAAAAAaQICYptkrBkUq%2Fo%2FsI5TEi3lgNg%3DnPgqOfuCugcbVRwVRdy8yMYTLPXCWGsxz2OmMBkke4cnf8t7jW'


#authenticate
auth = tweepy.Client(bearer_token=bearer_token, consumer_key=api_key,
                    consumer_secret=api_key_secret, access_token=access_token,
                    access_token_secret=access_token_secret)

#twitter id of science_news
science_news = "19402238"

def get_tweets(user):
    '''return list of last 5 tweets of given user'''
    id = user
    tweet_list = auth.get_users_tweets(id=id, max_results=5)

    return tweet_list.data








