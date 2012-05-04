using System;
using Microsoft.Win32;
using System.Runtime.InteropServices;
using System.Globalization;
using System.Security.Cryptography;


namespace AuthorizedURLProcessor
{
    /// <summary>
    /// Summary description for Class1.
    /// </summary>
    /// 

	public class URLProcessor
	{
        private static string password="";
        private static int timetolerance = 90;
		public URLProcessor()
		{
		}

		static URLProcessor()
		{
			RegistryKey localMachine = Registry.LocalMachine;
			localMachine= localMachine.OpenSubKey("Software\\Polox Group\\URLProtect");

			if( null != localMachine )
			{
				if (localMachine.GetValue("URLSecretPassword") != null)
				{
					password = (string)localMachine.GetValue("URLSecretPassword");
				}

				if (localMachine.GetValue("TimeDiffTolerance") != null)
				{
					timetolerance = (int)localMachine.GetValue("TimeDiffTolerance");
				}
			}

		}

        public URLValidationExceptionTyte CheckURLValidity(string url, string ip)
        {

            try
            {
                verifyURL(url, ip, password);
                return URLValidationExceptionTyte.SUCCESS;
            }
            // Add logging here.
            catch(URLValidationException e)
            {
                return e.getType();
            }
        }


        // mms://65.57.110.80/resourse_id?server_time=server_date_time&validminutes=1&hash_value=BASE64(MD5(ip+key+server_date_time))
        public string BuildProtectedURL(string media_url, string ip)
        {
            return BuildProtectedURLWithValidity(media_url, ip, 1);
        }

        public string BuildProtectedURLWithValidity(string media_url, string ip, int valid)
        {
            string result = null;
            DateTime cur_date = DateTime.Now;
            TimeZone localzone = TimeZone.CurrentTimeZone;

            DateTime localTime = localzone.ToUniversalTime(cur_date);

            string date_time = localTime.ToString(new CultureInfo("en-us"));

            Int32 Valid = valid;
            string to_be_hashed = ip + password + date_time + Valid.ToString();

            byte[] to_be_hashed_byte_array = new byte[to_be_hashed.Length];

            int i = 0;
            foreach (char cur_char in to_be_hashed)
            {
                to_be_hashed_byte_array[i++] = (byte)cur_char;
            }

            byte[] hash = (new MD5CryptoServiceProvider()).ComputeHash(to_be_hashed_byte_array);

            string md5_signature = Convert.ToBase64String(hash);

            result = media_url + "?server_time=" + date_time + "&hash_value=" + md5_signature + "&validminutes=" + Valid.ToString();
            return (result);
        }


        // mms://65.57.110.80/resourse_id?server_time=server_date_time&hash_value=BASE64(MD5(ip+key+server_date_time))

        private static string getParam(string source, string parameter_name)
        {
            int param_pos     = source.IndexOf(parameter_name);
            int param_pos_end = source.IndexOf('&', param_pos);

            if( ( -1 == param_pos ) || ( source.Length == param_pos ) )
            {
                throw new Exception();
            }
            param_pos+= parameter_name.Length;

            if( -1 == param_pos_end )
            {
                param_pos_end = source.Length;
            }

            return(source.Substring(param_pos,
                                    param_pos_end - param_pos) );
               

        }

        private void ParseURL(ref string url, ref string base64_md5_hash_value,
                              ref string script_server_time, ref string validminutes)
        {
            try
            {

                script_server_time    = getParam(url, "server_time=");
                validminutes          = getParam(url, "validminutes=");
                base64_md5_hash_value = getParam(url, "hash_value=");
                int params_begin = url.IndexOf('?');

                if( -1 == params_begin )
                {
                    throw new Exception();
                }

                url = url.Substring(0, params_begin);
            }
            catch(Exception)
            {
                throw new URLValidationException(URLValidationExceptionTyte.INVALID_URL);
            }
        }

        private void verifyURL(string url, string ip, string key)
        {
            string base64_md5_hash_value = null;
            string script_server_time    = null;
            string valid_minutes = null;

            ParseURL(ref url, ref base64_md5_hash_value, ref script_server_time, ref valid_minutes);
            string to_hash = ip + key + script_server_time + valid_minutes;
            byte[]  etalon_array = new byte[to_hash.Length];

            int i = 0;
            foreach (char cur_char in to_hash)
            {
                etalon_array[i++] = (byte)cur_char;
            }

            MD5CryptoServiceProvider md5 = new MD5CryptoServiceProvider();
            
            byte[] etalon_hash = md5.ComputeHash(etalon_array);
            
            byte[] md5_hash_value = Convert.FromBase64String(base64_md5_hash_value);

            if(etalon_hash.Length != md5_hash_value.Length )
            {
                throw new URLValidationException(URLValidationExceptionTyte.IT_IS_NOT_A_HASH);
            }

            int j = 0;
            foreach(byte cur_char in etalon_hash)
            {
                if( cur_char != md5_hash_value[j++] )
                {
                    throw new URLValidationException(URLValidationExceptionTyte.INVALID_HASH);
                }
            }

            try
            {
                // server time with UTC timezone
                DateTime server_time = DateTime.Parse(script_server_time,
                                                      new CultureInfo("en-us"),
                                                      DateTimeStyles.NoCurrentDateDefault);

                TimeZone localzone = TimeZone.CurrentTimeZone;

                DateTime localTime = localzone.ToLocalTime(server_time);

                DateTime cur_date = DateTime.Now;

                TimeSpan interval = cur_date.Subtract(localTime);

                // lets assume timetolerance second is possible time difference
                if (interval.TotalSeconds < -timetolerance)
                {
                    throw new URLValidationException(URLValidationExceptionTyte.TIME_MUST_BE_SYNCHRONIZED);
                }
                Int32 valid_minutes_int = Int32.Parse(valid_minutes);

                // url has been exrired
                if (interval.TotalMinutes > valid_minutes_int)
                {
                    throw new URLValidationException(URLValidationExceptionTyte.DATE_TIME_HAS_BEEN_EXPIRED);
                }

            }
            catch(FormatException)
            {
                throw new URLValidationException(URLValidationExceptionTyte.TIME_FORMAT_ERROR);
            }
        }
	}
}
