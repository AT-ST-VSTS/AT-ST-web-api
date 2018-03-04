using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;

namespace AT_ST_web_api.Controllers
{

    /// <summary>
    /// CRUD stuffs.
    /// </summary>
    [Produces("application/json")]
    [Route("api/[controller]")]
    public class ValuesController : Controller
    {
        /// <summary>
        /// Get stuffs.
        /// </summary>
        [HttpGet]
        public IEnumerable<string> Get()
        {
            return new string[] { "value1", "value2" };
        }

        /// <summary>
        /// Get a specific stuff.
        /// </summary>
        /// <param name="id"></param>
        [HttpGet("{id}")]
        public string Get(int id)
        {
            return "value";
        }

        /// <summary>
        /// Create a stuff.
        /// </summary>
        /// <param name="value"></param>
        /// <returns>A newly-created stuff</returns>
        /// <response code="201">Returns the newly-created stuff</response>
        /// <response code="400">If the stuff is null</response>
        /// <remarks>
        /// Sample request:
        ///
        ///     POST /stu
        ///     {
        ///        "id": 1,
        ///        "name": "Item1",
        ///        "isComplete": true
        ///     }
        ///
        /// </remarks>
        [HttpPost]
        public void Post([FromBody]string value)
        {
        }

        /// <summary>
        /// Update a specific stuff.
        /// </summary>
        /// <param name="id"></param>
        /// <param name="value"></param>
        [HttpPut("{id}")]
        public void Put(int id, [FromBody]string value)
        {
        }

        /// <summary>
        /// Delete a specific stuff.
        /// </summary>
        /// <param name="id"></param>
        [HttpDelete("{id}")]
        public void Delete(int id)
        {
        }
    }
}
