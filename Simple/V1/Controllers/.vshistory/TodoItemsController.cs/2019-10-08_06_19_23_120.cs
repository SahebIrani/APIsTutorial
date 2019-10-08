using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Mime;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

using Simple.Data;
using Simple.Models;

namespace Simple.V1.Controllers
{
    //[Authorize(Policy = "Over18")]
    [Controller]
    [ApiController]
    //[Route("v{version:apiVersion}/api/[controller]")]
    [Route("api/[controller]")]
    [Route("api/v{version:apiVersion}/[controller]")]
    //Specify a format
    //To restrict the response formats, apply the[Produces] filter.Like most Filters, [Produces] can be applied at the action, controller, or global scope:
    //[Produces("application/json")]
    [Produces(MediaTypeNames.Application.Json)]
    [Consumes(MediaTypeNames.Application.Json)]
    //Response format URL mappings
    //Clients can request a particular format as part of the URL, for example:
    //In the query string or part of the path.
    //By using a format-specific file extension such as .xml or.json.
    //The mapping from request path should be specified in the route the API is using. For example:
    //The preceding route allows the requested format to be specified as an optional file extension. The [FormatFilter] attribute checks for the existence of the format value in the RouteData and maps the response format to the appropriate formatter when the response is created.
    //Route Formatter
    ///api/products/5	The default output formatter
    ///api/products/5.json The JSON formatter(if configured)
    ///api/products/5.xml The XML formatter(if configured)
    //[FormatFilter]
    //Microsoft.AspNetCore.Mvc.ApiConventionMethodAttribute — Applies to individual actions and specifies the convention type and the convention method that applies.
    //In the following example, the default convention type's Microsoft.AspNetCore.Mvc.DefaultApiConventions.Put convention method is applied to the Update action:
    [ApiConventionType(typeof(DefaultApiConventions))]
    public class TodoItemsController : ControllerBase
    {
        public TodoItemsController(ApplicationDbContext context) =>
            Context = context ?? throw new ArgumentNullException(nameof(context));

        public ApplicationDbContext Context { get; }

        //[HttpPost("poop")]
        //public IActionResult PostPoop(TodoItem value, ApiVersion apiVersion)
        //{
        //    return CreatedAtAction(nameof(DummyController.Get), "Dummy",
        //        new
        //        {
        //            id = 3,
        //            version = apiVersion.ToString()
        //        },
        //        null);
        //}

        [HttpGet]
        public async IAsyncEnumerable<TodoItem> Get()
        {
            IAsyncEnumerable<TodoItem> todoItems = Context.TodoItems.AsNoTracking().AsAsyncEnumerable();
            await foreach (TodoItem item in todoItems) yield return item;
        }

        //متدهای HTTP          CRUD مثال
        //==============       =============       =================================
        //POST                 Create              Link to /customers/{id} شامل ID جدید
        //GET                  Read                نمایش لیستی از مشتریان، صفحه بندی
        //PUT                  Update/Replace      جایگزین کردن هر اسمی درون لیست مشتریان
        //PATCH                Update/Modify       ویرایش کردن یک نام از لیست تمام مشتریان
        //DELETE               Delete              حذف کردن نام یک مشتری و یا مشتریان

        //Examine the GET methods
        //These methods implement two GET endpoints:
        //GET /api/TodoItems
        //GET /api/TodoItems/{id}
        //Test the app by calling the two endpoints from a browser or Postman.For example:
        //https://localhost:5001/api/TodoItems
        //https://localhost:5001/api/TodoItems/1
        //[
        //  {
        //    "id": 1,
        //    "name": "Item1",
        //    "isComplete": false
        //  }
        //]

        //[HttpGet("[controller]/[action]/{id}", Name = "TodoItem")]
        [HttpGet("{id:long}", Name = "GetById")] // GET: api/TodoItems/5
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(TodoItem), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        // GET ~/api/v1/TodoItems/{id}
        // GET ~/api/TodoItems/{id}?api-version=1.0
        //[ApiVersion("1", Deprecated = true)]
        [Obsolete]
        [AllowAnonymous]
        public async Task<IActionResult> GetById(long id)
        {
            var todoItem = await Context.TodoItems.FindAsync(id);
            if (todoItem == null) return NotFound();
            return Ok(todoItem);
            //return new JsonResult(todoItem, new JsonSerializerOptions { WriteIndented = true });
            //return new JsonResult(todoItem, new JsonSerializerSettings { Formatting = Formatting.Indented });
        }

        // POST: api/TodoItems
        //[HttpPost("/AddTodoItem")]
        //[ProducesResponseType(200)]
        [HttpPost]
        [Consumes(MediaTypeNames.Application.Json)]
        [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(TodoItem))]
        [ProducesResponseType(StatusCodes.Status201Created)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [AllowAnonymous]
        public async Task<ActionResult<TodoItem>> PostTodoItem(TodoItem todoItem, CancellationToken ct = default)
        {
            if (!ModelState.IsValid)
            {
                //LogErrors(ModelState);
                //var loggerFactory = HttpContext.RequestServices.GetRequiredService<ILoggerFactory>();
                //var logger = loggerFactory.CreateLogger(HttpContext.ActionDescriptor.DisplayName);
                //var logger = loggerFactory.CreateLogger("YourCategory");
                return BadRequest(ModelState);
            }

            if (todoItem.Name.Contains("SinjulMSBH", StringComparison.Ordinal)) return BadRequest();

            await Context.TodoItems.AddAsync(todoItem, ct);
            await Context.SaveChangesAsync(ct);

            //The CreatedAtAction method:
            //Returns an HTTP 201 status code if successful.
            return CreatedAtAction(/*"GetTodoItem"*/nameof(GetById), new { id = todoItem.Id }, todoItem);
        }

        //Microsoft.AspNetCore.JsonPatch
        //Microsoft.AspNetCore.Mvc.NewtonsoftJson

        //JsonPatch in ASP.NET Core
        //The ASP.NET Core implementation of JSON Patch is provided in the Microsoft.AspNetCore.JsonPatch NuGet package.The package is included in the Microsoft.AspnetCore.App metapackage.

        //متد PATCH
        //این متد روشی دیگر برای آپدیت و بروزرسانی رکوردها می‌باشد با این تفاوت که پس از ارسال درخواست، تنها فیلدهایی که دارای مقادیر هستند تغییر می‌کنند و سایر فیلدها به قوت خود باقی می‌مانند.مثلا فرض کنید یک رکورد با نام کاربری و ایمیل در پایگاه داده‌ی خود ذخیره کرده‌اید و حال قصد بروزرسانی آن با متد PATCH را دارید.اگر فیلد نام کاربری را پر کنید و ایمیل را خالی بگذارید و سپس درخواست را ارسال کنید، تنها مقدار فیلد نام کاربری در پایگاه داده تغییر می‌کند و مقدار فیلد ایمیل تغییر نخواهد کرد.

        //متد PUT
        //متد PUT برای بروزرسانی(آپدیت) یک رکورد موجود و یا ساخت یک رکورد جدید(در صورت عدم وجود) کاربرد دارد.این متد مقدار جدید رکورد را در هر درخواست جایگزین می‌کند. یعنی به طور مشابه متد PUT ابتدا یک رکورد را پاک می‌کند و سپس یک رکورد جدید را ایجاد و در مکان رکورد قبلی با مقادیر جدید جایگزین می‌کند.بنابراین اگر چندین فیلد در یک درخواست PUT مقداری نداشته باشند، بدیهی‌ست که پس از آپدیت شدن مقدار null را در خود جایگزین می‌کنند.مثلا اگر یک کاربر دارای فیلدهای نام کاربری و ایمیل باشد و سپس متد PUT درخواستی را ارسال کند که تنها شامل فیلد نام کاربری باشد، فقط این فیلد تغییر می‌کند و فیلد ایمیل مقداری برابر null را دریافت خواهد کرد.

        //[HttpPatch("update")]
        //public Person Patch([FromBody]JsonPatchDocument<TodoItem> todiItemPatch)
        //{
        //    personPatch.ApplyTo(_defaultPerson);
        //    return _defaultPerson;
        //}

        //[HttpPatch]
        //public IActionResult JsonPatchWithModelState([FromBody] JsonPatchDocument<Customer> patchDoc)
        //{
        //    if (patchDoc != null)
        //    {
        //        var customer = CreateCustomer();

        //        patchDoc.ApplyTo(customer, ModelState);

        //        if (!ModelState.IsValid)
        //        {
        //            return BadRequest(ModelState);
        //        }

        //        return new ObjectResult(customer);
        //    }
        //    else
        //    {
        //        return BadRequest(ModelState);
        //    }
        //}

        //[HttpPatch]
        //public IActionResult JsonPatchForDynamic([FromBody]JsonPatchDocument patch)
        //{
        //    dynamic obj = new ExpandoObject();
        //    patch.ApplyTo(obj);

        //    return Ok(obj);
        //}

        //To test the sample, run the app and send HTTP requests with the following settings:

        //URL: http://localhost:{port}/jsonpatch/jsonpatchwithmodelstate
        //HTTP method: PATCH
        //Header: Content-Type: application/json-patch+json
        //Body: Copy and paste one of the JSON patch document samples from the JSON project folder.

        //[HttpPatch("update/{id}")]
        //public Person Patch(int id, [FromBody]JsonPatchDocument<PersonDTO> personPatch)
        //{
        //    PersonDatabase personDatabase = _personRepository.GetById(id); // Get our original person object from the database.
        //    PersonDTO personDTO = _mapper.Map<PersonDTO>(personDatabase); //Use Automapper to map that to our DTO object.

        //    personPatch.ApplyTo(personDTO); //Apply the patch to that DTO.

        //    _mapper.Map(personDTO, personDatabase); //Use automapper to map the DTO back ontop of the database object.

        //    _personRepository.Update(personDatabase); //Update our person in the database.

        //    return personDTO;
        //}

        // PUT: api/TodoItems/5
        [HttpPut("{id:long}")]
        [ProducesResponseType(StatusCodes.Status204NoContent)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesDefaultResponseType]
        public async Task<IActionResult> PutTodoItem(long id, TodoItem todoItem, CancellationToken ct = default)
        {
            if (id != todoItem.Id) return BadRequest();

            Context.Entry(todoItem).State = EntityState.Modified;
            //Context.TodoItems.Update(todoItem);

            try
            {
                await Context.SaveChangesAsync(ct);
            }
            catch (DbUpdateConcurrencyException)
            {
                var item = await Context.TodoItems.FindAsync(id);
                if (item != null) return NotFound();
                else throw;
            }

            //return NoContent();
            return Ok(todoItem);
        }

        // DELETE: api/TodoItems/5
        [HttpDelete("{id:long}")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesDefaultResponseType]
        public async Task<ActionResult<TodoItem>> DeleteTodoItem(long id, CancellationToken ct = default)
        {
            var todoItem = await Context.TodoItems.FindAsync(id);
            if (todoItem == null) return NotFound();

            Context.TodoItems.Remove(todoItem);
            await Context.SaveChangesAsync(ct);

            return todoItem;
        }

        // GET: api/TodoItems/search?namelike=th
        //[HttpGet("Search")]
        [HttpGet("Search/{namelike}")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(string), StatusCodes.Status404NotFound)]
        [ProducesDefaultResponseType]
        public async Task<IActionResult> Search(string namelike, CancellationToken ct = default)
        {
            var result = await Context.TodoItems.AsNoTracking().Where(c => c.Name.Contains(namelike)).ToListAsync(ct);
            return !result.Any() ? NotFound(namelike) : (IActionResult)Ok(result);
        }

    }
}
