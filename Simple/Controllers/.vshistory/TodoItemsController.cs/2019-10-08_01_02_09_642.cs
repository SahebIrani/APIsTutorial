using System;
using System.Collections.Generic;
using System.Net.Mime;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

using Simple.Data;
using Simple.Models;

namespace Simple.Controllers
{
    [Route("api/[controller]")]
    [Produces(MediaTypeNames.Application.Json)]
    [ApiController]
    [Controller]
    public class TodoItemsController : ControllerBase
    {
        public TodoItemsController(ApplicationDbContext context) =>
            Context = context ?? throw new ArgumentNullException(nameof(context));

        public ApplicationDbContext Context { get; }

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
        [HttpGet("{id:long}")] // GET: api/TodoItems/5
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<IActionResult> GetByIdAsync(long id)
        {
            var todoItem = await Context.TodoItems.FindAsync(id);
            if (todoItem == null) return NotFound();
            return Ok(todoItem);
        }

        // POST: api/TodoItems
        //[HttpPost("/AddTodoItem")]
        [HttpPost]
        [Consumes(MediaTypeNames.Application.Json)]
        [ProducesResponseType(StatusCodes.Status201Created)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public async Task<ActionResult<TodoItem>> PostTodoItem(TodoItem todoItem, CancellationToken ct = default)
        {
            if (todoItem.Name.Contains("SinjulMSBH", StringComparison.Ordinal)) return BadRequest();

            await Context.TodoItems.AddAsync(todoItem, ct);
            await Context.SaveChangesAsync(ct);

            //The CreatedAtAction method:
            //Returns an HTTP 201 status code if successful.
            return CreatedAtAction(/*"GetTodoItem"*/nameof(GetByIdAsync), new { id = todoItem.Id }, todoItem);
        }

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

            return NoContent();
        }

        // DELETE: api/TodoItems/5
        [HttpDelete("{id:long}")]
        public async Task<ActionResult<TodoItem>> DeleteTodoItem(long id, CancellationToken ct = default)
        {
            var todoItem = await Context.TodoItems.FindAsync(id);
            if (todoItem == null) return NotFound();

            Context.TodoItems.Remove(todoItem);
            await Context.SaveChangesAsync(ct);

            return todoItem;
        }

    }
}
