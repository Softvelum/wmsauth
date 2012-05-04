using System;
using System.Runtime.InteropServices;
namespace AuthorizedURLProcessor
{
	/// <summary>
	/// Summary description for URLValidationException.
	/// </summary>
	/// 
    [ComVisible(false)]
    public enum  URLValidationExceptionTyte { SUCCESS,
                                             DATE_TIME_HAS_BEEN_EXPIRED,
                                             TIME_MUST_BE_SYNCHRONIZED,
                                             INVALID_HASH,
                                             IT_IS_NOT_A_HASH,
                                             TIME_FORMAT_ERROR,
                                             INVALID_URL,
                                             UNKNOWN_ERROR};
    [ComVisible(false)]
    public class URLValidationException : Exception
	{
        private URLValidationExceptionTyte my_type = URLValidationExceptionTyte.UNKNOWN_ERROR;
		public URLValidationException(URLValidationExceptionTyte ex_type)
		{
            my_type = ex_type;
		}
        public URLValidationExceptionTyte getType()
        {
            return my_type;
        }
	}
}
