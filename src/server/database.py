from base64 import b64encode
from datetime import datetime
from configparser import ConfigParser
from uuid import UUID, uuid4

from bson.binary import Binary, UUID_SUBTYPE
from bson.json_util import default, dumps
from bson.objectid import ObjectId
from pymongo import MongoClient
from pymongo.collection import ReturnDocument


class ClipDatabase:

    def __init__(self):
        config = ConfigParser()
        config.read('config.ini')
        database_conf = config['database']
        self.client = MongoClient(
                database_conf['url'],
                int(database_conf['port']))
        self.db = getattr(self.client, database_conf['database'])
        self.clip_collection = self.db[database_conf['collection']]

    def _create_binary_uuid(self, _id):
        """
        Creates an Mongo binary uuid from the string-representation of a uuid4

        https://stackoverflow.com/questions/51283260/pymongo-uuid-search-not-returning-documents-that-definitely-exist
        """  # noqc
        if type(_id) is not str:
            _id = str(_id)

        bin_id = UUID(_id)
        bin_id = Binary(bin_id.bytes, UUID_SUBTYPE)
        return bin_id

    def _build_json_response_clip(self, clip):
        """
        The method strips the additional informations added by Mongo
        in order to return pure json
        i.e. convert uuid-objects to their string or hand binary
        """
        clip['_id'] = str(clip['_id'])

        if 'filename' in clip:
            data = b64encode(clip['data'])

            clip['data'] = str(data)[2:-1]

        return clip

    def save_clip(self, data):
        """
        Inserts a new clip-object into the database.

        :param content: The content of the new clip-object
        :return: A json-like string with the newly created object
        """
        _id = uuid4()
        _id = self._create_binary_uuid(str(_id))
        modified_date = datetime.now()

        new_clip = {
                '_id': _id,
                'data': data['content'],
                'mimetype': data['mimetype'],
                'last_modified': modified_date.isoformat()
        }

        if 'filename' in data:
            new_clip['filename'] = data['filename']

        insert_result = self.clip_collection.insert_one(new_clip)
        new_clip = self.clip_collection.find_one({'_id': _id})
        return dumps(self._build_json_response_clip(new_clip))

    def get_clip_by_id(self,  clip_id):
        """
        Searches the database for a clip with the specified id.

        :param id: The id to be searched. Has to be the string representation
                   of a uuid-object
        :return: Json-like string containing the found object or None
                 if no object with the id could be found in the database
        """
        clip_id = self._create_binary_uuid(clip_id)

        clip = self.clip_collection.find_one({'_id': clip_id})

        if clip is not None:
            clip = dumps(self._build_json_response_clip(clip))

        return clip

    def get_all_clips(self):
        """
        :return: Json-like string containing all clips
        """
        results = list(self.clip_collection.find({}))
        json_result = [self._build_json_response_clip(i) for i in results]
        return dumps(json_result)

    def update_clip(self, object_id, data):
        """
        Updates an existing clip-object with new data.

        :param object_id: Id of the object to be updated
        :param data: New data. For safety, you should not replace text with
                     a file and vice versa
        :return: Json string containing the newly updated object or None
                 if no object with the id could be found in the database
        """
        bin_id = self._create_binary_uuid(object_id)
        new_doc = self.clip_collection.find_one_and_replace(
                {'_id': bin_id},
                {'data': data['content']},
                return_document=ReturnDocument.AFTER
        )

        if new_doc is not None:  # When replace actually did take place
            new_doc = dumps(self._build_json_response_clip(new_doc))

        return new_doc

    def delete_entry_by_id(self, clip_id):
        """
        Deletes an object.
        :param clip_id: Id of the objecte to be deleted
        :return: Number of deleted objects. 
                 Can be zero, if no objects were deleted
        """
        bin_id = self._create_binary_uuid(clip_id)

        return self.clip_collection.delete_one({'_id': bin_id}).deleted_count