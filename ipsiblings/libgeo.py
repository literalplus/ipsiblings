# libgeo.py
#
# (c) 2018 Marco Starke
#
# Maxmind License CC BY-SA 4.0
# https://creativecommons.org/licenses/by-sa/4.0/
# This product includes GeoLite2 data created by MaxMind, available from http://www.maxmind.com.
#
# https://github.com/maxmind/GeoIP2-python
# https://dev.maxmind.com/geoip/geoip2/geolite2/
#
# > The GeoLite2 Country and City databases are updated on the first Tuesday of each month.
# > The GeoLite2 ASN database is updated every Tuesday.
# ==>> Update on Wednesday
#

import os
import io
import tarfile
import datetime
import urllib.request
import geoip2.database

import libconstants as const
import liblog
log = liblog.get_root_logger()



class Geo(object):

  def __init__(self, city_db_path = None, asn_db_path = None):
    """
    Load city database and ASN database.
    No parameters mean that the databases in const.GEO_DB_BASE_DIR will be loaded.
    If a database is not available it will be downloaded and reloaded.
    """
    self.city_dbreader = None
    self.asn_dbreader = None

    if city_db_path:
      self.city_db = city_db_path
    else:
      self.city_db = os.path.join(const.GEO_DB_BASE_DIR, const.GEO_CITY_DB_FILE)

    if asn_db_path:
      self.asn_db = asn_db_path
    else:
      self.asn_db = os.path.join(const.GEO_DB_BASE_DIR, const.GEO_ASN_DB_FILE)

    try: # if file is not found or corrupt download database
      self.city_dbreader = geoip2.database.Reader(self.city_db)
    except Exception as e:
      log.warning('Problem loading location database (trying to update now): {0} - {1}'.format(type(e).__name__, e))
      self._update_city()
      self.city_dbreader = geoip2.database.Reader(self.city_db)

    try:
      self.asn_dbreader = geoip2.database.Reader(self.asn_db)
    except Exception as e:
      log.warning('Problem loading ASN database (trying to update now): {0} - {1}'.format(type(e).__name__, e))
      self._update_asn()
      self.asn_dbreader = geoip2.database.Reader(self.asn_db)


  def _update_city(self):
    if self.city_dbreader:
      self.city_dbreader.close()

    httpresponse = urllib.request.urlopen(const.GEO_CITY_DB_URL)
    with tarfile.open(fileobj = io.BytesIO(httpresponse.read()), mode = "r:gz") as tf:
      db_file = next((s for s in tf.getmembers() if const.GEO_CITY_DB_FILE in s.name))
      db_file.name = os.path.basename(db_file.name)
      tf.extract(db_file, const.GEO_DB_BASE_DIR)


  def _update_asn(self):
    if self.asn_dbreader:
      self.asn_dbreader.close()

    httpresponse = urllib.request.urlopen(const.GEO_ASN_DB_URL)
    with tarfile.open(fileobj = io.BytesIO(httpresponse.read()), mode = "r:gz") as tf:
      db_file = next((s for s in tf.getmembers() if const.GEO_ASN_DB_FILE in s.name))
      db_file.name = os.path.basename(db_file.name)
      tf.extract(db_file, const.GEO_DB_BASE_DIR)


  def update_databases(self, force = False):
    """
    Loads the creation dates from the databases and checks if updated versions are available.
    The update frequency is based on the information provided by MaxMind:
    City DB -> 1st Tuesday each month
    ASN DB -> each Tuesday
    """

    if force:
      log.info('Forced database update ...')
      self._update_city()
      self._update_asn()
      # reopen databases
      self.city_dbreader = geoip2.database.Reader(self.city_db)
      self.asn_dbreader = geoip2.database.Reader(self.asn_db)
      return

    city_meta = self.city_dbreader.metadata()
    asn_meta = self.asn_dbreader.metadata()

    city_date = datetime.date.fromtimestamp(city_meta.build_epoch)
    asn_date = datetime.date.fromtimestamp(asn_meta.build_epoch)

    today = datetime.date.today()

    one_day = datetime.timedelta(days = 1)
    one_week = datetime.timedelta(weeks = 1)

    iterdate = today.replace(day = 1) # first day of current month

    while iterdate.weekday() != 1: # 0 = Mo, 1 = Tu, 2 = We, ...
      iterdate = iterdate + one_day # get the first Tu of the month

    # if current date is at least 1 day ahead of the MaxMind update policy
    # and the update policy date is at least one cycle ahead of the local database date
    if iterdate < today and iterdate > city_date:
      log.info('Updating MaxMind location database from {0} to {1} ...'.format(city_date, iterdate))
      self._update_city()
    else:
      log.info('CITY database is already the newest version!')

    if asn_date + one_week < today:
      new_db_date = today - one_week

      while new_db_date.weekday() != 1: # Tuesday
        new_db_date = new_db_date + one_day
      log.info('Updating MaxMind ASN database from {0} to {1} ...'.format(asn_date, new_db_date))
      self._update_asn()
    else:
      log.info('ASN database is already the newest version!')

    # reopen databases
    self.city_dbreader = geoip2.database.Reader(self.city_db)
    self.asn_dbreader = geoip2.database.Reader(self.asn_db)


  def city(self, ip, locale = 'en', raw = False):
    """
    Returns a dict containing available information or None if address was not found.

    ip           IP address to query
    locale       language of the returned information ['en']
    raw          return the original model acquired from the geoip2 database reader [False]

    locale may be one of [ de, en, es, fr, ja, pt-BR, ru, zh-CN ]

    Remark: English (en) will always be available but if an entry does not have an e.g. german (de)
    entry, None will be returned although an english version would be available!
    """
    try:
      res = self.city_dbreader.city(ip)
    except Exception as e:
      log.debug('Exception: {0} - {1}'.format(type(e).__name__, e))
      return None

    if raw:
      return res.raw

    info = {}

    # information available
    # [ 'city', 'continent', 'country', 'location', 'postal', 'raw', 'registered_country', 'represented_country', 'subdivisions', 'traits' ]

    # object information
    # city : ['confidence', 'geoname_id', 'name', 'names']
    # continent : ['code', 'geoname_id', 'name', 'names']
    # country : ['confidence', 'geoname_id', 'is_in_european_union', 'iso_code', 'name', 'names']
    # location : ['accuracy_radius', 'average_income', 'latitude', 'longitude', 'metro_code', 'population_density', 'postal_code', 'postal_confidence', 'time_zone']
    # postal : ['code', 'confidence']
    # raw : ['clear', 'copy', 'fromkeys', 'get', 'items', 'keys', 'pop', 'popitem', 'setdefault', 'update', 'values']
    # registered_country : ['confidence', 'geoname_id', 'is_in_european_union', 'iso_code', 'name', 'names']
    # represented_country : ['confidence', 'geoname_id', 'is_in_european_union', 'iso_code', 'name', 'names', 'type']
    # subdivisions : ['count', 'index', 'most_specific']
    # traits : ['autonomous_system_number', 'autonomous_system_organization', 'connection_type', 'domain', 'ip_address', 'is_anonymous', 'is_anonymous_proxy', 'is_anonymous_vpn', 'is_hosting_provider', 'is_legitimate_proxy', 'is_public_proxy', 'is_satellite_provider', 'is_tor_exit_node', 'isp', 'organization', 'user_type']

    info['city'] = res.city.names.get(locale)

    info['country'] = res.country.names.get(locale)
    info['country_iso_code'] = res.country.iso_code
    info['country_is_in_european_union'] = res.country.is_in_european_union

    info['continent'] = res.continent.names.get(locale)
    info['continent_code'] = res.continent.code

    info['location_lat'] = res.location.latitude
    info['location_long'] = res.location.longitude
    info['location_accuracy'] = res.location.accuracy_radius
    info['location_timezone'] = res.location.time_zone

    info['postal_code'] = res.postal.code

    # info['raw'] = res.raw

    info['registered_country'] = res.registered_country.names.get(locale)
    info['registered_country_iso_code'] = res.registered_country.iso_code
    info['registered_country_is_in_european_union'] = res.registered_country.is_in_european_union

    # info['represented_country'] = res.represented_country.names.get(locale)
    # info['represented_country_iso_code'] = res.represented_country.iso_code
    # info['represented_country_is_in_european_union'] = res.represented_country.is_in_european_union

    info['subdivision'] = res.subdivisions.most_specific.names.get(locale)

    info['ip'] = res.traits.ip_address
    # info['asn'] = res.traits.autonomous_system_number

    return info


  def asn(self, ip, locale = 'en', raw = False):
    """
    Returns a dict containing available information or None if address was not found.

    ip           IP address to query
    locale       language of the returned information ['en']
    raw          return the original model acquired from the geoip2 database reader [False]

    locale may be one of [ de, en, es, fr, ja, pt-BR, ru, zh-CN ]

    Remark: English (en) will always be available but if an entry does not have an e.g. german (de)
    entry, None will be returned although an english version would be available!
    """
    try:
      res = self.asn_dbreader.asn(ip)
    except Exception as e:
      log.debug('Exception: {0} - {1}'.format(type(e).__name__, e))
      return None

    if raw:
      return res.raw

    info = {}

    # information available
    # [ 'autonomous_system_number', 'autonomous_system_organization', 'ip_address', 'raw' ]

    info['autonomous_system_number'] = res.autonomous_system_number
    info['autonomous_system_organization'] = res.autonomous_system_organization
    info['ip_address'] = res.ip_address
    # info['raw'] = res.raw

    return info


  def match(self, ip4, ip6, get_diffs = False):
    """
    Compares geolocation information of an IPv4/IPv6 address pair.
    Returns True/False if not get_diffs, otherwise -> (True/False, { diff_key: (v4 value, v6 value) }, geodata4, geodata6)
    If get_diffs is False, the function will immediately return at the first difference.
    Otherwise, all keys will be compared and distinct values collected and returned.

    Keys which will be compared:
    city_keys = [ 'country_iso_code', 'continent_code' ]
    Keys which will be ignored:
    asn_keys = ['autonomous_system_number'] -> may not match but raw ts value matches => sibling but distinct AS => ignore ASN
    city_keys = [ 'city', 'country', 'country_is_in_european_union', 'continent', 'registered_country_iso_code', 'registered_country_is_in_european_union', 'location_lat', 'location_long', 'location_accuracy', 'location_timezone', 'postal_code', 'registered_country', 'subdivision', 'ip' ] -> very often differ but raw ts value matches
    """
    # a4 = self.asn(ip4)
    # a6 = self.asn(ip6)
    c4 = self.city(ip4)
    c6 = self.city(ip6)

    # if all([a4, a6]):
    #   asn_available = True
    # else:
    #   asn_available = False
    asn_available = False # DO NOT CHECK FOR ASNs

    if all([c4, c6]):
      city_available = True
    else:
      city_available = False

    if not city_available and not asn_available:
      if get_diffs:
        return (None, None, None, None)
      else:
        return None

    city_keys = [ 'country_iso_code', 'continent_code' ]
    asn_keys = ['autonomous_system_number']

    differences = {}
    data4 = {}
    data6 = {}

    if asn_available:
      for key in asn_keys:
        data4[key] = a4[key]
        data6[key] = a6[key]
        if a4[key] != a6[key]:
          if get_diffs:
            differences[key] = (a4[key], a6[key])
          else:
            return False

    if city_available:
      for key in city_keys:
        data4[key] = c4[key]
        data6[key] = c6[key]
        if str(c4[key]).lower().strip() != str(c6[key]).lower().strip():
          if get_diffs:
            differences[key] = (c4[key], c6[key])
          else:
            return False

    if get_diffs:
      if differences:
        return (False, differences, data4, data6)
      else:
        return (True, differences, data4, data6)
    else:
      return True
